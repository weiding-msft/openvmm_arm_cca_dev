// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Support for loading a TMK into VM memory.

use anyhow::Context as _;
use fs_err::File;
use guestmem::GuestMemory;
use hvdef::Vtl;
use loader::importer::GuestArch;
use loader::importer::ImageLoad;
use loader::importer::X86Register;
use std::fmt::Debug;
use std::sync::Arc;
use virt::VpIndex;
use vm_topology::memory::MemoryLayout;
use vm_topology::processor::ProcessorTopology;
use vm_topology::processor::aarch64::Aarch64Topology;
use vm_topology::processor::x86::X86Topology;

use nix::{
    sys::{
        mman::{MapFlags, ProtFlags, mmap},
        statfs::statfs,
    },
    unistd::{ftruncate, mkstemp, unlink},
};
use std::{
    num::NonZeroUsize,
    os::unix::{fs::FileExt, io::FromRawFd},
    path::Path,
};

/// Loads a TMK, returning the initial registers for the BSP.
#[cfg_attr(not(guest_arch = "x86_64"), expect(dead_code))]
pub fn load_x86(
    offset_addr: Option<u64>,
    memory_layout: &MemoryLayout,
    guest_memory: &GuestMemory,
    processor_topology: &ProcessorTopology<X86Topology>,
    caps: &virt::x86::X86PartitionCapabilities,
    tmk: &File,
) -> anyhow::Result<Arc<virt::x86::X86InitialRegs>> {
    let mut loader = vm_loader::Loader::new(guest_memory.clone(), memory_layout, Vtl::Vtl0);
    let load_info = load_binary(offset_addr, &mut loader, tmk)?;

    let page_table_base = load_info.next_available_address;
    let page_tables = page_table::x64::build_page_tables_64(
        page_table_base,
        0,
        page_table::IdentityMapSize::Size4Gb,
        None,
    );
    loader
        .import_pages(
            page_table_base >> 12,
            page_tables.len() as u64 >> 12,
            "page_tables",
            loader::importer::BootPageAcceptance::Exclusive,
            &page_tables,
        )
        .context("failed to import page tables")?;

    let gdt_base = page_table_base + page_tables.len() as u64;
    loader::common::import_default_gdt(&mut loader, gdt_base >> 12)
        .context("failed to import gdt")?;

    let mut import_reg = |reg| {
        loader
            .import_vp_register(reg)
            .context("failed to set register")
    };
    import_reg(X86Register::Cr0(x86defs::X64_CR0_PG | x86defs::X64_CR0_PE))?;
    import_reg(X86Register::Cr3(page_table_base))?;
    import_reg(X86Register::Cr4(x86defs::X64_CR4_PAE))?;
    import_reg(X86Register::Efer(
        x86defs::X64_EFER_SCE
            | x86defs::X64_EFER_LME
            | x86defs::X64_EFER_LMA
            | x86defs::X64_EFER_NXE,
    ))?;
    import_reg(X86Register::Rip(load_info.entrypoint))?;

    let regs = vm_loader::initial_regs::x86_initial_regs(
        &loader.initial_regs(),
        caps,
        &processor_topology.vp_arch(VpIndex::BSP),
    );
    Ok(regs)
}

/// Memory-maps a region of a given size using a temporary file on a hugetlbfs filesystem.
///
/// # Arguments
/// * `template` - A path template for the temporary file (e.g., "/dev/hugepages/myapp-XXXXXX").
///   This path must point to a location on a mounted `hugetlbfs` filesystem and end with "XXXXXX".
/// * `size` - The desired size of the memory mapping in bytes. Must be a multiple of the huge page size.
///
/// # Returns
/// A `Result` containing the memory address of the mapping as a `u64` integer,
/// or a `String` with a descriptive error message on failure.
///
/// # Safety
/// The `u64` returned is a memory address. The caller is responsible for eventually unmapping this
/// memory by casting the `u64` back to a pointer and using it with `nix::sys::mman::munmap`.
/// The function itself contains unsafe blocks for interacting with low-level OS APIs.
pub unsafe fn mmap_hugetlbfs(htlbfs_mount_dir: &Path, size: u64) -> Result<u64, String> {
    // 1. Perform preliminary checks on the requested size.
    if size == 0 {
        return Err("A mapping size of 0 is not permitted".to_string());
    }
    let size_as_usize = usize::try_from(size).map_err(|_| {
        format!("The requested size of {size} bytes is too large for this platform's address space")
    })?;
    let size_as_i64 = i64::try_from(size).map_err(|_| {
        format!("The requested size of {size} bytes is too large for an i64 offset")
    })?;
    let non_zero_size =
        NonZeroUsize::new(size_as_usize).expect("Size was already checked to be non-zero");

    let mpath = htlbfs_mount_dir.join("kvmtools-XXXXXX");
    if mpath.exists() {
        std::fs::remove_file(&mpath).map_err(|e| {
            format!(
                "Failed to remove existing file at '{}': {}",
                mpath.display(),
                e
            )
        })?;
    }

    let sfs = statfs(htlbfs_mount_dir).map_err(|e| {
        format!(
            "Failed to stat filesystem at '{}': {}",
            htlbfs_mount_dir.display(),
            e
        )
    })?;

    // 3. Verify that the filesystem is indeed hugetlbfs.
    if sfs.filesystem_type() != nix::sys::statfs::HUGETLBFS_MAGIC {
        return Err(format!(
            "The path '{}' is not on a hugetlbfs filesystem",
            htlbfs_mount_dir.display()
        ));
    }

    // 4. Validate the huge page size (block size) against the requested mapping size.
    let blk_size = sfs.block_size() as u64;
    if blk_size == 0 || blk_size > size {
        return Err(format!(
            "Invalid hugetlbfs page size ({blk_size} bytes) for the requested memory size ({size} bytes)"
        ));
    }

    // 5. Create a unique temporary file using the user-provided template.
    let (fd, mpath) = mkstemp(&mpath).map_err(|e| {
        format!(
            "Failed to create temporary file using template '{}': {}",
            mpath.display(),
            e
        )
    })?;

    // --- Start of RAII-managed resource scope ---
    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    // 6. Immediately unlink the file from the filesystem.
    unlink(&mpath).map_err(|e| {
        format!(
            "Failed to unlink temporary file at '{}': {}",
            mpath.display(),
            e
        )
    })?;

    // 7. Set the file size to the desired mapping size.
    ftruncate(&file, size_as_i64)
        .map_err(|e| format!("Failed to truncate temporary file to {size} bytes: {e}"))?;

    // 8. Memory-map the file.
    let addr = unsafe {
        mmap(
            None,
            non_zero_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE,
            &file,
            0,
        )
    }
    .map_err(|e| format!("Failed to memory-map {size} bytes: {e}"))?;
    // --- End of RAII-managed resource scope ---

    // 9. Return the memory address cast to a u64 integer.
    Ok(addr.as_ptr() as u64)
}

/// For a given virtual address, finds the corresponding Physical Frame Number (PFN).
///
/// This function reads the `/proc/self/pagemap` file to translate a virtual address
/// from the current process's address space into a physical frame number.
///
/// # Arguments
/// * `vaddr` - The virtual address to look up, provided as a `u64`.
///
/// # Returns
/// A `Result` containing the Physical Frame Number (PFN) as a `u64`,
/// or a `String` with a descriptive error message on failure.
///
/// # Safety
/// This function is `unsafe` because:
/// 1. It directly interacts with the low-level `/proc/self/pagemap` interface.
/// 2. The caller must ensure `vaddr` is a valid virtual address within the process's
///    address space. An invalid address may still produce a result, but it will be
///    for an unrelated page.
/// 3. Reading `/proc/self/pagemap` typically requires `CAP_SYS_ADMIN` privileges.
pub unsafe fn virt_to_phys(vaddr: u64) -> Result<u64, String> {
    // Constants based on the kernel's pagemap documentation.
    const PFN_BITS: u64 = 55;
    const PFN_MASK: u64 = (1 << PFN_BITS) - 1;
    const PAGE_PRESENT_BIT: u64 = 1 << 63;
    const PAGEMAP_ENTRY_SIZE: u64 = size_of::<u64>() as u64;

    // Get the system's page size. This is more reliable than using a hardcoded value.
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap() as u64;
    if page_size == 0 {
        return Err("Could not determine system page size".to_string());
    }
    // dbg!(page_size);

    // Open the pagemap file for the current process.
    let pagemap_file = std::fs::File::open("/proc/self/pagemap").map_err(|e| {
        format!("Failed to open /proc/self/pagemap (requires root or CAP_SYS_ADMIN): {e}")
    })?;

    // Each entry in pagemap is 8 bytes. Calculate the offset for the desired page.
    // Virtual Page Number = Virtual Address / Page Size
    // Offset = Virtual Page Number * Entry Size
    let offset = (vaddr / page_size) * PAGEMAP_ENTRY_SIZE;
    // dbg!(offset);

    let mut entry_bytes = [0u8; 8];
    // Use `read_exact_at` to perform an atomic seek-and-read. This is safer than
    // separate lseek() and read() calls, especially in multithreaded programs.
    pagemap_file
        .read_exact_at(&mut entry_bytes, offset)
        .map_err(|e| format!("Failed to read from /proc/self/pagemap at offset {offset}: {e}"))?;
    // dbg!(entry_bytes);

    let pagemap_entry = u64::from_ne_bytes(entry_bytes);

    // According to the kernel documentation, bit 63 indicates if the page is present in RAM.
    // If it's not present, the PFN bits are invalid (they may contain swap info).
    if (pagemap_entry & PAGE_PRESENT_BIT) == 0 {
        return Err(format!(
            "Page for virtual address {vaddr:#x} is not present in RAM (swapped out or not mapped)"
        ));
    }

    // The lower 55 bits contain the PFN.
    let pfn = pagemap_entry & PFN_MASK;
    Ok(pfn * page_size)
}

#[cfg_attr(not(guest_arch = "aarch64"), expect(dead_code))]
pub fn load_aarch64(
    load_offset: Option<u64>,
    memory_layout: &MemoryLayout,
    guest_memory: &GuestMemory,
    processor_topology: &ProcessorTopology<Aarch64Topology>,
    caps: &virt::aarch64::Aarch64PartitionCapabilities,
    tmk: &File,
) -> anyhow::Result<Arc<virt::aarch64::Aarch64InitialRegs>> {
    // TODO: CCA: fix guest_memory to match the hugetlbfs memory we mapped above
    let mut loader = vm_loader::Loader::new(guest_memory.clone(), memory_layout, Vtl::Vtl0);
    let load_info = load_binary(load_offset, &mut loader, tmk)?;

    let mut import_reg = |reg| {
        loader
            .import_vp_register(reg)
            .context("failed to set register")
    };

    // dbg!(&load_info.entrypoint);
    import_reg(loader::importer::Aarch64Register::Pc(load_info.entrypoint))?;
    let regs = vm_loader::initial_regs::aarch64_initial_regs(
        &loader.initial_regs(),
        caps,
        &processor_topology.vp_arch(VpIndex::BSP),
    );

    Ok(regs)
}

fn load_binary<R: Debug + GuestArch>(
    offset_addr: Option<u64>,
    loader: &mut vm_loader::Loader<'_, R>,
    tmk: &File,
) -> anyhow::Result<loader::elf::LoadInfo> {
    // TODO: CCA: fix start address and load offset

    loader::elf::load_static_elf(
        loader,
        &mut &*tmk,
        0,
        offset_addr.unwrap_or(0x98000000),
        false,
        loader::importer::BootPageAcceptance::Exclusive,
        "tmk",
    )
    .context("failed to load tmk")
}

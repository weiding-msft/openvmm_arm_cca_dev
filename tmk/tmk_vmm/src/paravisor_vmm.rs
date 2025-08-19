// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Support for running as a paravisor VMM.

#![cfg(target_os = "linux")]

use crate::run::CommonState;
use crate::run::RunnerBuilder;
use core::slice;
use guestmem::GuestMemory;
use openhcl_dma_manager::AllocationVisibility;
use openhcl_dma_manager::DmaClientParameters;
use openhcl_dma_manager::LowerVtlPermissionPolicy;
use openhcl_dma_manager::OpenhclDmaManager;
use std::sync::Arc;
use virt::Partition;
use virt_mshv_vtl::UhLateParams;
use virt_mshv_vtl::UhPartitionNewParams;
use virt_mshv_vtl::UhProcessorBox;

impl CommonState {
    pub async fn run_paravisor_vmm(
        &mut self,
        isolation: virt::IsolationType,
    ) -> anyhow::Result<()> {
        let params = UhPartitionNewParams {
            isolation,
            hide_isolation: false,
            lower_vtl_memory_layout: &self.memory_layout,
            topology: &self.processor_topology,
            cvm_cpuid_info: None,
            snp_secrets: None,
            env_cvm_guest_vsm: false,
            vtom: None,
            handle_synic: true,
            no_sidecar_hotplug: false,
            use_mmio_hypercalls: false,
            intercept_debug_exceptions: false,
        };
        let p = virt_mshv_vtl::UhProtoPartition::new(params, |_| self.driver.clone())?;

        let vtom = if cfg!(guest_arch = "aarch64") {
            Some(1 << (p.realm_config().ipa_width() - 1))
        } else {
            None
        };

        if cfg!(guest_arch = "aarch64") {
            p.cca_set_mem_perm(
                self.hugetlb_memory.as_ref().unwrap().pa,
                self.hugetlb_memory.as_ref().unwrap().pa
                    + self.hugetlb_memory.as_ref().unwrap().size,
            )
            .expect("failed to set CCA memory permissions");
        }

        let m = underhill_mem::init(&underhill_mem::Init {
            processor_topology: &self.processor_topology,
            isolation,
            vtl0_alias_map_bit: None,
            vtom,
            mem_layout: &self.memory_layout,
            complete_memory_layout: &self.memory_layout,
            boot_init: None,
            shared_pool: &[],
            maximum_vtl: hvdef::Vtl::Vtl0,
        })
        .await?;

        let dma_manager = OpenhclDmaManager::new(
            &[],
            &self
                .memory_layout
                .ram()
                .iter()
                .map(|r| r.range)
                .collect::<Vec<_>>(),
            vtom.unwrap_or(0),
        )
        .expect("failed to create global dma manager");
        // Needed because if we use the same DMA manager for both below,
        // the shared manager will end up allocating some pages at the start of the address space,
        // which will conflict with the private allocations and erase some of the ELF sections
        // of the TMK.
        let shared_dma_manager = OpenhclDmaManager::new(
            &[],
            &self
                .shared_memory_layout
                .ram()
                .iter()
                .map(|r| r.range)
                .collect::<Vec<_>>(),
            vtom.unwrap_or(0),
        )
        .expect("failed to create global dma manager");

        let (partition, vps) = p
            .build(UhLateParams {
                gm: [
                    m.vtl0().clone(),
                    m.vtl1().cloned().unwrap_or(GuestMemory::empty()),
                ]
                .into(),
                #[cfg(guest_arch = "x86_64")]
                cpuid: Vec::new(),
                crash_notification_send: mesh::channel().0,
                vmtime: &self.vmtime_source,
                cvm_params: Some(virt_mshv_vtl::CvmLateParams {
                    shared_gm: m.cvm_memory().unwrap().shared_gm.clone(),
                    isolated_memory_protector: m.cvm_memory().unwrap().protector.clone(),
                    shared_dma_client: shared_dma_manager.new_client(DmaClientParameters {
                        device_name: "partition-shared".into(),
                        lower_vtl_policy: LowerVtlPermissionPolicy::Any,
                        allocation_visibility: AllocationVisibility::Private,
                        persistent_allocations: true,
                    })?,
                    private_dma_client: dma_manager.new_client(DmaClientParameters {
                        device_name: "partition-private".into(),
                        lower_vtl_policy: LowerVtlPermissionPolicy::Any,
                        allocation_visibility: AllocationVisibility::Private,
                        persistent_allocations: true,
                    })?,
                }),
            })
            .await?;

        let partition = Arc::new(partition);

        self.run(m.vtl0(), partition.caps(), async |this, runner| {
            let [vp] = vps.try_into().ok().unwrap();
            start_vp(vp, runner, this.hugetlb_memory.as_ref().unwrap().va + 0x248).await?;
            Ok(())
        })
        .await
    }
}

async fn start_vp(
    mut vp: UhProcessorBox,
    mut runner: RunnerBuilder,
    va: u64,
) -> anyhow::Result<()> {
    std::thread::spawn(move || {
        let pool = pal_uring::IoUringPool::new("vp", 256).unwrap();
        let driver = pool.client().initiator().clone();
        pool.client().set_idle_task(async move |mut control| {
            // TODO: CCA: this is CCA-specific, we should have a way to
            // configure the backing processor for the VP.
            let vp = vp
                .bind_processor::<virt_mshv_vtl::CcaBacked>(&driver, Some(&mut control))
                .unwrap();

            runner.build(vp).unwrap().run_vp().await;
        });
        pool.run()
    });
    Ok(())
}

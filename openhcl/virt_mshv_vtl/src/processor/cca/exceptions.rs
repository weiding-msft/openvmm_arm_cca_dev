// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::CcaRunLoopError;
use super::MmioBus;
use super::SyncExit;
use hcl::protocol;

fn access_size_bytes(sas: u8) -> Result<u8, CcaRunLoopError> {
    match sas {
        0 => Ok(1),
        1 => Ok(2),
        2 => Ok(4),
        3 => Ok(8),
        _ => Err(CcaRunLoopError::UnsupportedMmioAccessSize(sas)),
    }
}

fn decode_data_abort(esr_el2: u64) -> Result<(aarch64defs::IssDataAbort, u8), CcaRunLoopError> {
    let esr = aarch64defs::EsrEl2::from(esr_el2);
    let ec = aarch64defs::ExceptionClass(esr.ec());
    if ec != aarch64defs::ExceptionClass::DATA_ABORT
        && ec != aarch64defs::ExceptionClass::DATA_ABORT_LOWER
    {
        return Err(CcaRunLoopError::InvalidDataAbortSyndrome);
    }

    let iss = aarch64defs::IssDataAbort::from(esr.iss());
    if !iss.isv() {
        return Err(CcaRunLoopError::InvalidDataAbortSyndrome);
    }

    let instruction_size = if esr.il() { 4 } else { 2 };
    Ok((iss, instruction_size))
}

fn decode_fault_ipa(far_el2: u64, hpfar_el2: u64) -> u64 {
    let page_offset = far_el2 & 0xfff;
    let base = hpfar_el2 << 8;
    if base == 0 {
        far_el2
    } else {
        base | page_offset
    }
}

pub fn dispatch_sync_exit(
    run: &mut protocol::cca_rsi_plane_run,
    mmio: &mut impl MmioBus,
) -> Result<SyncExit, CcaRunLoopError> {
    let esr = aarch64defs::EsrEl2::from(run.exit.esr_el2);
    let ec = aarch64defs::ExceptionClass(esr.ec());
    if ec != aarch64defs::ExceptionClass::DATA_ABORT
        && ec != aarch64defs::ExceptionClass::DATA_ABORT_LOWER
    {
        return Ok(SyncExit::Unhandled {
            esr_el2: run.exit.esr_el2,
            far_el2: run.exit.far_el2,
            hpfar_el2: run.exit.hpfar_el2,
        });
    }

    let (iss, instruction_size) = decode_data_abort(run.exit.esr_el2)?;
    let size = access_size_bytes(iss.sas())?;
    let register_index = iss.srt();
    let address = decode_fault_ipa(run.exit.far_el2, run.exit.hpfar_el2);

    run.entry.gprs = run.exit.gprs;

    if iss.wnr() {
        let mut bytes = [0u8; 8];
        let reg_value = if register_index < 31 {
            run.entry.gprs[register_index as usize]
        } else {
            0
        };
        bytes.copy_from_slice(&reg_value.to_le_bytes());
        mmio.mmio_write(address, &bytes[..size as usize]);
    } else {
        let mut bytes = [0u8; 8];
        mmio.mmio_read(address, &mut bytes[..size as usize]);
        if register_index < 31 {
            run.entry.gprs[register_index as usize] = u64::from_le_bytes(bytes);
        }
    }

    run.entry.pc = run.entry.pc.wrapping_add(instruction_size as u64);

    Ok(SyncExit::DataAbortMmio {
        address,
        size,
        is_write: iss.wnr(),
        register_index,
    })
}

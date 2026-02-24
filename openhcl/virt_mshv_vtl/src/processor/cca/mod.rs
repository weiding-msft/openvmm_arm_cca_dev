// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM CCA processor run-loop skeleton.
//!
//! This module intentionally provides only the basic structure for the CCA
//! execution loop:
//! `prepare_entry -> plane_enter -> dispatch_exit`.
//! It is feature-gated and not wired into default processor selection.

mod exceptions;
mod state;

use hcl::protocol;
use hcl::protocol::cca_rsi_plane_exit_reason;
use state::CcaVpState;
use thiserror::Error;

/// Backend abstraction used by the CCA run loop to enter the lower plane.
pub trait PlaneEnterBackend {
    /// Performs one plane entry and updates `run.exit` on return.
    fn plane_enter(
        &mut self,
        run: &mut protocol::cca_rsi_plane_run,
    ) -> Result<(), CcaRunLoopError>;
}

/// Result of dispatching a CCA plane exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchExit {
    /// Synchronous exit that must be handled by exception dispatch.
    Sync(SyncExit),
    /// IRQ exit path.
    Irq,
    /// FIQ exit path.
    Fiq,
}

/// Minimal synchronous-exit payload used by the run-loop skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncExit {
    /// Data-abort MMIO was handled and execution can continue.
    DataAbortMmio {
        address: u64,
        size: u8,
        is_write: bool,
        register_index: u8,
    },
    /// Synchronous exit type is currently unhandled.
    Unhandled {
        esr_el2: u64,
        far_el2: u64,
        hpfar_el2: u64,
    },
}

/// Minimal MMIO bus contract used by the CCA run-loop path.
pub trait MmioBus {
    fn mmio_read(&mut self, address: u64, data: &mut [u8]);
    fn mmio_write(&mut self, address: u64, data: &[u8]);
}

/// CCA run-loop skeleton errors.
#[derive(Debug, Error)]
pub enum CcaRunLoopError {
    /// Plane entry failed.
    #[error("plane enter failed")]
    PlaneEnter,
    /// Exit reason from plane entry was not recognized.
    #[error("unexpected CCA exit reason {0:#x}")]
    UnexpectedExitReason(u64),
    /// Data abort ISS was malformed or unsupported.
    #[error("invalid data-abort syndrome")]
    InvalidDataAbortSyndrome,
    /// Data-abort MMIO access width is unsupported.
    #[error("unsupported MMIO access size {0}")]
    UnsupportedMmioAccessSize(u8),
    /// Minimal state validation failed.
    #[error("invalid CCA VP state: {0}")]
    InvalidState(&'static str),
}

/// CCA run-loop skeleton state.
pub struct CcaRunLoop<B: PlaneEnterBackend> {
    backend: B,
    run: protocol::cca_rsi_plane_run,
    state: CcaVpState,
}

impl<B: PlaneEnterBackend> CcaRunLoop<B> {
    /// Creates a new run loop using the given backend.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            run: protocol::cca_rsi_plane_run::default(),
            state: CcaVpState::default(),
        }
    }

    /// Executes a single run-loop iteration.
    pub fn run_once(&mut self, mmio: &mut impl MmioBus) -> Result<DispatchExit, CcaRunLoopError> {
        self.prepare_entry()?;
        self.plane_enter()?;
        self.state.capture_from_exit(&self.run.exit);
        self.run.entry.gprs = self.run.exit.gprs;
        self.run.entry.gicv3_hcr = self.run.exit.gicv3_hcr;
        self.run.entry.gicv3_lrs = self.run.exit.gicv3_lrs;

        let exit = self.dispatch_exit(mmio)?;
        self.state.capture_from_entry(&self.run.entry)?;
        Ok(exit)
    }

    /// Mutable access to the shared run structure.
    pub fn run_state_mut(&mut self) -> &mut protocol::cca_rsi_plane_run {
        &mut self.run
    }

    /// Immutable access to the shared run structure.
    pub fn run_state(&self) -> &protocol::cca_rsi_plane_run {
        &self.run
    }

    fn prepare_entry(&mut self) -> Result<(), CcaRunLoopError> {
        // Entry setup for follow-up PRs (state save/restore and controls).
        self.state.restore_for_entry(&mut self.run.entry)?;
        self.run.entry.flags = 0;
        Ok(())
    }

    fn plane_enter(&mut self) -> Result<(), CcaRunLoopError> {
        self.backend.plane_enter(&mut self.run)
    }

    fn dispatch_exit(&mut self, mmio: &mut impl MmioBus) -> Result<DispatchExit, CcaRunLoopError> {
        match self.run.exit.reason() {
            cca_rsi_plane_exit_reason::SYNC => Ok(DispatchExit::Sync(
                exceptions::dispatch_sync_exit(&mut self.run, mmio)?,
            )),
            cca_rsi_plane_exit_reason::IRQ => Ok(DispatchExit::Irq),
            cca_rsi_plane_exit_reason::FIQ => Ok(DispatchExit::Fiq),
            _ => Err(CcaRunLoopError::UnexpectedExitReason(
                self.run.exit.exit_reason,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockMmio {
        reads: Vec<(u64, usize)>,
        writes: Vec<(u64, Vec<u8>)>,
        read_value: u64,
    }

    impl MmioBus for MockMmio {
        fn mmio_read(&mut self, address: u64, data: &mut [u8]) {
            self.reads.push((address, data.len()));
            let bytes = self.read_value.to_le_bytes();
            data.copy_from_slice(&bytes[..data.len()]);
        }

        fn mmio_write(&mut self, address: u64, data: &[u8]) {
            self.writes.push((address, data.to_vec()));
        }
    }

    struct MockBackend {
        exit_reason: u64,
        esr_el2: u64,
        far_el2: u64,
        hpfar_el2: u64,
        gpr_value: u64,
    }

    impl PlaneEnterBackend for MockBackend {
        fn plane_enter(
            &mut self,
            run: &mut protocol::cca_rsi_plane_run,
        ) -> Result<(), CcaRunLoopError> {
            run.exit.exit_reason = self.exit_reason;
            run.exit.esr_el2 = self.esr_el2;
            run.exit.far_el2 = self.far_el2;
            run.exit.hpfar_el2 = self.hpfar_el2;
            run.exit.gprs[0] = self.gpr_value;
            Ok(())
        }
    }

    fn make_data_abort_esr(is_write: bool, register_index: u8, size_bytes: u8) -> u64 {
        let sas = match size_bytes {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => panic!("unsupported test size"),
        };

        let iss = aarch64defs::IssDataAbort::new()
            .with_isv(true)
            .with_wnr(is_write)
            .with_sas(sas)
            .with_srt(register_index)
            .with_sf(true);

        let esr = aarch64defs::EsrEl2::from(iss)
            .with_ec(aarch64defs::ExceptionClass::DATA_ABORT_LOWER.0)
            .with_il(true);
        u64::from(esr)
    }

    fn run_for_mmio(size_bytes: u8, is_write: bool) -> (CcaRunLoop<MockBackend>, MockMmio, DispatchExit) {
        let ipa = 0x1234_5000u64;
        let far = ipa;
        let hpfar = (ipa & !0xfffu64) >> 8;

        let backend = MockBackend {
            exit_reason: cca_rsi_plane_exit_reason::SYNC.0,
            esr_el2: make_data_abort_esr(is_write, 0, size_bytes),
            far_el2: far,
            hpfar_el2: hpfar,
            gpr_value: 0x8877_6655_4433_2211,
        };

        let mut loop_state = CcaRunLoop::new(backend);
        loop_state.run_state_mut().entry.pc = 0x1000;
        let mut mmio = MockMmio {
            read_value: 0x1122_3344_5566_7788,
            ..Default::default()
        };
        let exit = loop_state.run_once(&mut mmio).unwrap();
        (loop_state, mmio, exit)
    }

    #[test]
    fn data_abort_mmio_read_sizes_are_handled() {
        for size in [1u8, 2, 4, 8] {
            let (loop_state, mmio, exit) = run_for_mmio(size, false);
            assert_eq!(mmio.reads.len(), 1);
            assert_eq!(mmio.reads[0].1, size as usize);
            assert_eq!(mmio.writes.len(), 0);
            assert!(matches!(
                exit,
                DispatchExit::Sync(SyncExit::DataAbortMmio {
                    is_write: false,
                    size: s,
                    register_index: 0,
                    ..
                }) if s == size
            ));
            assert_eq!(loop_state.run_state().entry.pc, 0x1004);
        }
    }

    #[test]
    fn data_abort_mmio_write_sizes_are_handled() {
        for size in [1u8, 2, 4, 8] {
            let (loop_state, mmio, exit) = run_for_mmio(size, true);
            assert_eq!(mmio.writes.len(), 1);
            assert_eq!(mmio.writes[0].1.len(), size as usize);
            assert_eq!(mmio.reads.len(), 0);
            assert!(matches!(
                exit,
                DispatchExit::Sync(SyncExit::DataAbortMmio {
                    is_write: true,
                    size: s,
                    register_index: 0,
                    ..
                }) if s == size
            ));
            assert_eq!(loop_state.run_state().entry.pc, 0x1004);
        }
    }

    struct ContinuityBackend {
        iteration: usize,
        expected_pc: u64,
        expected_x0: u64,
        expected_hcr: u64,
        expected_lr0: u64,
    }

    impl PlaneEnterBackend for ContinuityBackend {
        fn plane_enter(
            &mut self,
            run: &mut protocol::cca_rsi_plane_run,
        ) -> Result<(), CcaRunLoopError> {
            assert_eq!(run.entry.pc, self.expected_pc);
            assert_eq!(run.entry.gprs[0], self.expected_x0);
            assert_eq!(run.entry.gicv3_hcr, self.expected_hcr);
            assert_eq!(run.entry.gicv3_lrs[0], self.expected_lr0);

            run.exit.exit_reason = cca_rsi_plane_exit_reason::SYNC.0;
            run.exit.esr_el2 = make_data_abort_esr(false, 0, 8);
            run.exit.far_el2 = 0x3000_0000;
            run.exit.hpfar_el2 = (0x3000_0000 & !0xfffu64) >> 8;
            run.exit.gprs = run.entry.gprs;
            run.exit.gicv3_hcr = self.expected_hcr.wrapping_add(1);
            run.exit.gicv3_lrs[0] = self.expected_lr0.wrapping_add(1);

            let next_iteration = self.iteration + 1;
            self.expected_x0 = (next_iteration as u64) * 0x11;
            self.iteration = next_iteration;
            self.expected_pc = self.expected_pc.wrapping_add(4);
            self.expected_hcr = self.expected_hcr.wrapping_add(1);
            self.expected_lr0 = self.expected_lr0.wrapping_add(1);
            Ok(())
        }
    }

    #[test]
    fn context_state_is_continuous_across_iterations() {
        let mmio_values = [
            0x11u64,
            0x22u64,
            0x33u64,
            0x44u64,
            0x55u64,
            0x66u64,
            0x77u64,
            0x88u64,
        ];

        #[derive(Default)]
        struct SeqMmio {
            values: std::collections::VecDeque<u64>,
        }

        impl MmioBus for SeqMmio {
            fn mmio_read(&mut self, _address: u64, data: &mut [u8]) {
                let value = self.values.pop_front().unwrap();
                let bytes = value.to_le_bytes();
                data.copy_from_slice(&bytes[..data.len()]);
            }

            fn mmio_write(&mut self, _address: u64, _data: &[u8]) {}
        }

        let backend = ContinuityBackend {
            iteration: 0,
            expected_pc: 0x4000,
            expected_x0: 0,
            expected_hcr: 0,
            expected_lr0: 0,
        };

        let mut run_loop = CcaRunLoop::new(backend);
        run_loop.run_state_mut().entry.pc = 0x4000;
        let mut mmio = SeqMmio {
            values: mmio_values.into(),
        };

        for expected in [0x11u64, 0x22, 0x33, 0x44, 0x55] {
            let exit = run_loop.run_once(&mut mmio).unwrap();
            assert!(matches!(
                exit,
                DispatchExit::Sync(SyncExit::DataAbortMmio {
                    is_write: false,
                    size: 8,
                    register_index: 0,
                    ..
                })
            ));
            assert_eq!(run_loop.run_state().entry.gprs[0], expected);
        }
    }
}
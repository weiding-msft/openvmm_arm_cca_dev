// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM CCA processor run-loop skeleton.
//!
//! This module intentionally provides only the basic structure for the CCA
//! execution loop:
//! `prepare_entry -> plane_enter -> dispatch_exit`.
//! It is feature-gated and not wired into default processor selection.

use hcl::protocol;
use hcl::protocol::cca_rsi_plane_exit_reason;
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
pub struct SyncExit {
    pub esr_el2: u64,
    pub far_el2: u64,
    pub hpfar_el2: u64,
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
}

/// CCA run-loop skeleton state.
pub struct CcaRunLoop<B: PlaneEnterBackend> {
    backend: B,
    run: protocol::cca_rsi_plane_run,
}

impl<B: PlaneEnterBackend> CcaRunLoop<B> {
    /// Creates a new run loop using the given backend.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            run: protocol::cca_rsi_plane_run::default(),
        }
    }

    /// Executes a single run-loop iteration.
    pub fn run_once(&mut self) -> Result<DispatchExit, CcaRunLoopError> {
        self.prepare_entry();
        self.plane_enter()?;
        self.dispatch_exit()
    }

    /// Mutable access to the shared run structure.
    pub fn run_state_mut(&mut self) -> &mut protocol::cca_rsi_plane_run {
        &mut self.run
    }

    /// Immutable access to the shared run structure.
    pub fn run_state(&self) -> &protocol::cca_rsi_plane_run {
        &self.run
    }

    fn prepare_entry(&mut self) {
        // Entry setup for follow-up PRs (state save/restore and controls).
        self.run.entry.flags = 0;
    }

    fn plane_enter(&mut self) -> Result<(), CcaRunLoopError> {
        self.backend.plane_enter(&mut self.run)
    }

    fn dispatch_exit(&self) -> Result<DispatchExit, CcaRunLoopError> {
        match self.run.exit.reason() {
            cca_rsi_plane_exit_reason::SYNC => Ok(DispatchExit::Sync(SyncExit {
                esr_el2: self.run.exit.esr_el2,
                far_el2: self.run.exit.far_el2,
                hpfar_el2: self.run.exit.hpfar_el2,
            })),
            cca_rsi_plane_exit_reason::IRQ => Ok(DispatchExit::Irq),
            cca_rsi_plane_exit_reason::FIQ => Ok(DispatchExit::Fiq),
            _ => Err(CcaRunLoopError::UnexpectedExitReason(
                self.run.exit.exit_reason,
            )),
        }
    }
}
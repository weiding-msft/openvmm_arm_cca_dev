// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::CcaRunLoopError;
use hcl::protocol;

/// Minimal CCA VP state persisted across plane transitions.
#[derive(Debug, Clone)]
pub struct CcaVpState {
    initialized: bool,
    pc: u64,
    gprs: [u64; 31],
    gicv3_hcr: u64,
    gicv3_lrs: [u64; 16],
}

impl Default for CcaVpState {
    fn default() -> Self {
        Self {
            initialized: false,
            pc: 0,
            gprs: [0; 31],
            gicv3_hcr: 0,
            gicv3_lrs: [0; 16],
        }
    }
}

impl CcaVpState {
    /// Restores persisted state into the next plane entry payload.
    pub fn restore_for_entry(
        &self,
        entry: &mut protocol::cca_rsi_plane_entry,
    ) -> Result<(), CcaRunLoopError> {
        if !self.initialized {
            return Ok(());
        }

        entry.pc = self.pc;
        entry.gprs = self.gprs;
        entry.gicv3_hcr = self.gicv3_hcr;
        entry.gicv3_lrs = self.gicv3_lrs;

        self.validate_entry(entry)
    }

    /// Captures guest register/control state from plane exit.
    pub fn capture_from_exit(&mut self, exit: &protocol::cca_rsi_plane_exit) {
        self.gprs = exit.gprs;
        self.gicv3_hcr = exit.gicv3_hcr;
        self.gicv3_lrs = exit.gicv3_lrs;
        self.initialized = true;
    }

    /// Captures the next-entry state after exit dispatch handling.
    pub fn capture_from_entry(
        &mut self,
        entry: &protocol::cca_rsi_plane_entry,
    ) -> Result<(), CcaRunLoopError> {
        self.validate_entry(entry)?;

        self.pc = entry.pc;
        self.gprs = entry.gprs;
        self.gicv3_hcr = entry.gicv3_hcr;
        self.gicv3_lrs = entry.gicv3_lrs;
        self.initialized = true;
        Ok(())
    }

    fn validate_entry(
        &self,
        entry: &protocol::cca_rsi_plane_entry,
    ) -> Result<(), CcaRunLoopError> {
        // Minimal validation: lower-plane PC should remain instruction-aligned.
        if (entry.pc & 1) != 0 {
            return Err(CcaRunLoopError::InvalidState("unaligned entry PC"));
        }

        Ok(())
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM CCA Realm Service Interface (RSI) - Clean Implementation
//!
//! This module provides a clean, type-safe interface to the ARM CCA RSI.
//! The RSI is the interface through which Realm software communicates with
//! the Realm Management Monitor (RMM).
//!
//! # Architecture
//!
//! ```
//! ┌─────────────────────────────────────┐
//! │     High-level RSI Operations       │
//! │  (rsi_version, rsi_realm_config)    │
//! └────────────┬────────────────────────┘
//!              │
//! ┌────────────▼────────────────────────┐
//! │       RsiClient Trait               │
//! │  (Abstraction for RSI calls)        │
//! └────────────┬────────────────────────┘
//!              │
//!       ┌──────┴──────┐
//!       │             │
//! ┌─────▼─────┐ ┌────▼──────┐
//! │  Kernel   │ │   Mock    │
//! │  Driver   │ │  Client   │
//! └───────────┘ └───────────┘
//! ```

// | Command Name          | Full SMC ID    | Function Number |
// |-----------------------|----------------|-----------------|
// | RSI_VERSION           | 0xC400_0190    | 0x190          |
// | RSI_FEATURES          | 0xC400_0191    | 0x191          |
// | RSI_REALM_CONFIG      | 0xC400_0196    | 0x196          |
// | RSI_IPA_STATE_SET     | 0xC400_0197    | 0x197          |
// | RSI_HOST_CALL         | 0xC400_0199    | 0x199          |
// | RSI_MEM_GET_PERM_VALUE| 0xC400_01A0    | 0x1A0          |
// | RSI_MEM_SET_PERM_INDEX| 0xC400_01A1    | 0x1A1          |
// | RSI_MEM_SET_PERM_VALUE| 0xC400_01A2    | 0x1A2          |
// | RSI_PLANE_ENTER       | 0xC400_01A3    | 0x1A3          |
// | RSI_PLANE_SYSREG_READ | 0xC400_01AE    | 0x1AE          |
// | RSI_PLANE_SYSREG_WRITE| 0xC400_01AF    | 0x1AF          |



#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;
use bitfield_struct::bitfield;
use open_enum::open_enum;

/// SMC calling convention for ARM CCA RSI calls
///
/// The RSI uses the ARM SMCCC (SMC Calling Convention) to invoke
/// services from the RMM. The function identifier encodes:
/// - Fast vs Yielding call
/// - 32-bit vs 64-bit convention
/// - Service owner (ARM architecture for RSI)
/// - Function number
#[bitfield(u32)]
#[derive(PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct SmcFunctionId {
    /// Function number within the service
    #[bits(16)]
    pub function_num: u16,
    /// Service owner identifier
    /// 0x3F = ARM Architecture calls (which includes RSI)
    #[bits(6)]
    pub owner: u8,
    /// Must be 1 for 64-bit calling convention
    pub is_smc64: bool,
    /// Fast (1) vs Yielding (0) call
    pub is_fast: bool,
    #[bits(8)]
    _reserved: u8,
}

open_enum! {
    /// RSI command identifiers
    ///
    /// These are the function identifiers for the various RSI commands
    /// as defined in the ARM CCA firmware specification.
    pub enum RsiCommand: SmcFunctionId {
        /// Query the RSI version
        /// Returns: (lower_version, higher_version) in X1
        VERSION = SmcFunctionId::new()
            .with_owner(0x3F)     // ARM Architecture calls, Bits 16-21: 00_1111_11 
            .with_is_fast(true)   // Bit 31:     1
            .with_is_smc64(true)  // Bit 30:     1
            .with_function_num(0x190), // Bits 0-15:  0000_0001_1001_0000

        /// Query RSI features
        /// Input: Feature index in X1
        /// Returns: Feature value in X1
        FEATURES = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x191),

        /// Get realm configuration
        /// Input: Address of config structure in X1
        /// Returns: IPA width, algorithm, etc.
        REALM_CONFIG = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x196),

        /// Set IPA state (private, shared, destroyed)
        /// Input: Base IPA in X1, Top IPA in X2, State in X3, Flags in X4
        /// Returns: Top of processed range in X1
        IPA_STATE_SET = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x197),

        /// Get IPA state
        /// Input: IPA in X1
        /// Returns: State in X1
        IPA_STATE_GET = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x198),

        /// Host call (communicate with host)
        /// Input: GPRS for host call
        /// Returns: Result from host
        HOST_CALL = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x199),

        /// Get memory permission value
        /// Input: Permission index in X1
        /// Returns: Permission value in X1
        MEM_GET_PERM_VALUE = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x1A0),

        /// Set memory permission index for a range
        /// Input: Base IPA in X1, Top IPA in X2, Permission index in X3
        /// Returns: Top of processed range in X1
        MEM_SET_PERM_INDEX = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x1A1),

        /// Set memory permission value
        /// Input: Permission index in X1, Permission value in X2
        MEM_SET_PERM_VALUE = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x1A2),

        /// Enter a lower privilege plane
        /// Input: Physical address of plane_run structure in X1
        /// Returns: Exit information in plane_run structure
        PLANE_ENTER = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x1A3),

        /// Read a system register from a plane
        /// Input: Register encoding in X1
        /// Returns: Register value in X1
        PLANE_SYSREG_READ = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x1AE),

        /// Write a system register to a plane
        /// Input: Register encoding in X1, Value in X2
        PLANE_SYSREG_WRITE = SmcFunctionId::new()
            .with_owner(0x3F)
            .with_is_fast(true)
            .with_is_smc64(true)
            .with_function_num(0x1AF),
    }
}

open_enum! {
    /// RSI return codes
    ///
    /// These are returned in X0 by RSI calls to indicate success or
    /// the type of error that occurred.
    pub enum RsiReturnCode: i32 {
        /// The operation completed successfully
        SUCCESS = 0,

        /// Invalid input parameters
        ERROR_INPUT = -1,

        /// Invalid state for this operation
        ERROR_STATE = -2,

        /// Operation is incomplete, call again
        INCOMPLETE = -3,

        /// Unknown error occurred
        ERROR_UNKNOWN = -4,

        /// Device-specific error
        ERROR_DEVICE = -5,
    }
}

impl fmt::Display for RsiReturnCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RsiReturnCode::SUCCESS => write!(f, "SUCCESS"),
            RsiReturnCode::ERROR_INPUT => write!(f, "ERROR_INPUT"),
            RsiReturnCode::ERROR_STATE => write!(f, "ERROR_STATE"),
            RsiReturnCode::INCOMPLETE => write!(f, "INCOMPLETE"),
            RsiReturnCode::ERROR_UNKNOWN => write!(f, "ERROR_UNKNOWN"),
            RsiReturnCode::ERROR_DEVICE => write!(f, "ERROR_DEVICE"),
            RsiReturnCode(code) => write!(f, "Unknown({})", code),
        }
    }
}

/// Input parameters for an RSI call
#[derive(Debug, Clone, Copy)]
pub struct RsiInput {
    /// The RSI command to execute
    pub command: RsiCommand,
    /// Input arguments in registers X1-X7
    pub args: [u64; 7],
}

impl RsiInput {
    /// Create a new RSI input with the given command and no arguments
    pub const fn new(command: RsiCommand) -> Self {
        Self {
            command,
            args: [0; 7],
        }
    }

    /// Set argument at the given index (0-6 for X1-X7)
    pub fn with_arg(mut self, index: usize, value: u64) -> Self {
        assert!(index < 7, "Argument index must be 0-6");
        self.args[index] = value;
        self
    }
}

/// Output from an RSI call
#[derive(Debug, Clone, Copy)]
pub struct RsiOutput {
    /// Return code in X0
    pub return_code: RsiReturnCode,
    /// Output values in registers X1-X7
    pub results: [u64; 7],
}

impl RsiOutput {
    /// Check if the call was successful
    pub fn is_success(&self) -> bool {
        self.return_code == RsiReturnCode::SUCCESS
    }

    /// Get result at the given index (0-6 for X1-X7)
    pub fn result(&self, index: usize) -> u64 {
        assert!(index < 7, "Result index must be 0-6");
        self.results[index]
    }
}

/// Error type for RSI operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsiError {
    /// RSI call returned an error code
    RsiError(RsiReturnCode),
    /// Invalid input parameters to high-level function
    InvalidInput,
    /// Operation not supported
    NotSupported,
}

impl fmt::Display for RsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RsiError::RsiError(code) => write!(f, "RSI error: {}", code),
            RsiError::InvalidInput => write!(f, "Invalid input"),
            RsiError::NotSupported => write!(f, "Not supported"),
        }
    }
}

impl From<RsiReturnCode> for RsiError {
    fn from(code: RsiReturnCode) -> Self {
        RsiError::RsiError(code)
    }
}

/// Trait for performing RSI calls
///
/// This trait abstracts the mechanism for issuing RSI calls, allowing
/// for different implementations (kernel driver, direct SMC, mock, etc.)
pub trait RsiClient: Send + Sync {
    /// Execute an RSI call
    fn call(&self, input: RsiInput) -> Result<RsiOutput, RsiError>;
}

/// IPA (Intermediate Physical Address) state
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpaState {
    /// IPA is not assigned to the realm
    Empty = 0,
    /// IPA was assigned but is now destroyed
    Destroyed = 1,
    /// IPA is shared with the host
    Shared = 2,
}

/// Realm configuration returned by RSI_REALM_CONFIG
#[derive(Debug, Clone, Copy)]
pub struct RealmConfig {
    /// IPA width in bits (e.g., 40 means 1TB address space)
    pub ipa_width: u8,
    /// Hash algorithm used for measurements
    pub hash_algorithm: HashAlgorithm,
}

impl RealmConfig {
    /// Get the VTOM (Virtual Top of Memory) bit position
    ///
    /// This is the bit that distinguishes shared from private memory.
    /// For IPA width N, VTOM is bit N-1.
    pub fn vtom_bit(&self) -> u8 {
        self.ipa_width - 1
    }

    /// Get the VTOM mask value
    ///
    /// This can be OR'd with an address to make it shared.
    pub fn vtom_mask(&self) -> u64 {
        1u64 << self.vtom_bit()
    }
}

/// Hash algorithm used for realm measurements
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256 = 0,
    Sha512 = 1,
}

// =============================================================================
// High-level RSI operations
// =============================================================================

/// Query the RSI version
///
/// Returns (major, minor) version tuple.
///
/// # Example
/// ```ignore
/// let (major, minor) = rsi_version(&client)?;
/// assert!(major >= 1);
/// ```
pub fn rsi_version(client: &dyn RsiClient) -> Result<(u16, u16), RsiError> {
    let output = client.call(RsiInput::new(RsiCommand::VERSION))?;

    if !output.is_success() {
        return Err(output.return_code.into());
    }

    let version = output.result(0);
    let lower = (version & 0xFFFF) as u16;
    let higher = ((version >> 16) & 0xFFFF) as u16;

    Ok((lower, higher))
}

/// Get realm configuration
///
/// Returns the configuration of the current realm, including IPA width
/// and hash algorithm.
///
/// # Example
/// ```ignore
/// let config = rsi_realm_config(&client)?;
/// println!("IPA width: {} bits", config.ipa_width);
/// println!("VTOM mask: {:#x}", config.vtom_mask());
/// ```
pub fn rsi_realm_config(client: &dyn RsiClient) -> Result<RealmConfig, RsiError> {
    let output = client.call(RsiInput::new(RsiCommand::REALM_CONFIG))?;

    if !output.is_success() {
        return Err(output.return_code.into());
    }

    let ipa_width = output.result(0);
    let algorithm = output.result(1);

    if ipa_width > 52 {
        return Err(RsiError::InvalidInput);
    }

    let hash_algorithm = match algorithm {
        0 => HashAlgorithm::Sha256,
        1 => HashAlgorithm::Sha512,
        _ => return Err(RsiError::InvalidInput),
    };

    Ok(RealmConfig {
        ipa_width: ipa_width as u8,
        hash_algorithm,
    })
}

/// Set IPA state for a range of addresses
///
/// Changes the state of a range of IPAs (e.g., from private to shared).
/// The operation may be incomplete if the range is too large; in that case,
/// the returned value indicates where to continue.
///
/// # Arguments
/// * `base` - Start of the IPA range (inclusive)
/// * `top` - End of the IPA range (exclusive)
/// * `state` - The state to set
/// * `flags` - Additional flags (currently reserved, use 0)
///
/// # Returns
/// The top of the processed range. If this is less than the requested `top`,
/// call again with `base` set to the returned value.
///
/// # Example
/// ```ignore
/// let mut current = base;
/// while current < top {
///     current = rsi_ipa_state_set(&client, current, top, IpaState::Shared, 0)?;
/// }
/// ```
pub fn rsi_ipa_state_set(
    client: &dyn RsiClient,
    base: u64,
    top: u64,
    state: IpaState,
    flags: u64,
) -> Result<u64, RsiError> {
    if base >= top {
        return Err(RsiError::InvalidInput);
    }

    let input = RsiInput::new(RsiCommand::IPA_STATE_SET)
        .with_arg(0, base)
        .with_arg(1, top)
        .with_arg(2, state as u64)
        .with_arg(3, flags);

    let output = client.call(input)?;

    if !output.is_success() && output.return_code != RsiReturnCode::INCOMPLETE {
        return Err(output.return_code.into());
    }

    Ok(output.result(0))
}

/// Get IPA state for an address
///
/// Queries the state of a specific IPA.
pub fn rsi_ipa_state_get(client: &dyn RsiClient, ipa: u64) -> Result<IpaState, RsiError> {
    let input = RsiInput::new(RsiCommand::IPA_STATE_GET).with_arg(0, ipa);

    let output = client.call(input)?;

    if !output.is_success() {
        return Err(output.return_code.into());
    }

    match output.result(0) {
        0 => Ok(IpaState::Empty),
        1 => Ok(IpaState::Destroyed),
        2 => Ok(IpaState::Shared),
        _ => Err(RsiError::InvalidInput),
    }
}

/// Set memory permissions for a range of addresses
///
/// Sets the Stage 2 permission index for a range of IPAs.
///
/// # Arguments
/// * `base` - Start of the IPA range (inclusive)
/// * `top` - End of the IPA range (exclusive)
/// * `perm_index` - Permission index to set (0-15)
///
/// # Returns
/// The top of the processed range.
pub fn rsi_mem_set_perm_index(
    client: &dyn RsiClient,
    base: u64,
    top: u64,
    perm_index: u8,
) -> Result<u64, RsiError> {
    if base >= top || perm_index > 15 {
        return Err(RsiError::InvalidInput);
    }

    let input = RsiInput::new(RsiCommand::MEM_SET_PERM_INDEX)
        .with_arg(0, base)
        .with_arg(1, top)
        .with_arg(2, perm_index as u64);

    let output = client.call(input)?;

    if !output.is_success() && output.return_code != RsiReturnCode::INCOMPLETE {
        return Err(output.return_code.into());
    }

    Ok(output.result(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Mock RSI client for testing
    struct MockRsiClient {
        version: (u16, u16),
        ipa_width: u8,
        call_count: AtomicU64,
    }

    impl MockRsiClient {
        fn new() -> Self {
            Self {
                version: (1, 0),
                ipa_width: 40,
                call_count: AtomicU64::new(0),
            }
        }
    }

    impl RsiClient for MockRsiClient {
        fn call(&self, input: RsiInput) -> Result<RsiOutput, RsiError> {
            self.call_count.fetch_add(1, Ordering::Relaxed);

            let mut output = RsiOutput {
                return_code: RsiReturnCode::SUCCESS,
                results: [0; 7],
            };

            match input.command {
                RsiCommand::VERSION => {
                    let version = (self.version.0 as u64) | ((self.version.1 as u64) << 16);
                    output.results[0] = version;
                }
                RsiCommand::REALM_CONFIG => {
                    output.results[0] = self.ipa_width as u64;
                    output.results[1] = 0; // SHA256
                }
                RsiCommand::IPA_STATE_SET => {
                    output.results[0] = input.args[1]; // Return top
                }
                _ => {
                    output.return_code = RsiReturnCode::ERROR_UNKNOWN;
                }
            }

            Ok(output)
        }
    }

    #[test]
    fn test_rsi_version() {
        let client = MockRsiClient::new();
        let (major, minor) = rsi_version(&client).unwrap();
        assert_eq!(major, 1);
        assert_eq!(minor, 0);
    }

    #[test]
    fn test_realm_config() {
        let client = MockRsiClient::new();
        let config = rsi_realm_config(&client).unwrap();
        assert_eq!(config.ipa_width, 40);
        assert_eq!(config.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(config.vtom_bit(), 39);
        assert_eq!(config.vtom_mask(), 1u64 << 39);
    }

    #[test]
    fn test_ipa_state_set() {
        let client = MockRsiClient::new();
        let base = 0x1000;
        let top = 0x2000;
        let result = rsi_ipa_state_set(&client, base, top, IpaState::Shared, 0).unwrap();
        assert_eq!(result, top);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM CCA RSI ioctl adapter.

use rsi::RsiClient;
use rsi::RsiError;
use rsi::RsiInput;
use rsi::RsiOutput;
use rsi::RsiReturnCode;
use memory_range::MemoryRange;
use std::os::fd::RawFd;
use thiserror::Error;

const MSHV_IOCTL: u8 = 0xb8;
const MSHV_RSI_CALL: u8 = 0x3a;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MshvRsiCall {
    vp_index: u32,  // which virtual processor (vCPU) to target
    command: u32,   // RSI command ID
    args: [u64; 7], // RSI command arguments
    results: [u64; 7], // kernel fills up to command results
    return_code: i32, // kernel fills RSI command return code
}

mod ioctls {
    use super::MSHV_IOCTL;
    use super::MSHV_RSI_CALL;
    use super::MshvRsiCall;

    nix::ioctl_readwrite_bad!(
        mshv_rsi_call,
        nix::request_code_readwrite!(MSHV_IOCTL, MSHV_RSI_CALL, size_of::<MshvRsiCall>()),
        MshvRsiCall
    );
}

trait RsiIoctlBackend: Send + Sync {
    fn call(&self, fd: RawFd, payload: &mut MshvRsiCall) -> Result<(), nix::Error>;
}

#[derive(Debug, Default, Clone, Copy)]
struct LibcRsiIoctlBackend;

impl RsiIoctlBackend for LibcRsiIoctlBackend {
    fn call(&self, fd: RawFd, payload: &mut MshvRsiCall) -> Result<(), nix::Error> {
        // SAFETY: The ioctl number and payload type match the kernel ABI for
        // MSHV_RSI_CALL. The kernel validates payload contents.
        unsafe {
            ioctls::mshv_rsi_call(fd, payload)?;
        }
        Ok(())
    }
}

/// Kernel-backed RSI client that forwards typed RSI calls through MSHV ioctls.
pub struct KernelRsiClient {
    fd: RawFd,
    vp_index: u32,
    backend: Box<dyn RsiIoctlBackend>,
}

impl KernelRsiClient {
    /// Creates a new kernel RSI client.
    pub fn new(fd: RawFd, vp_index: u32) -> Self {
        Self {
            fd,
            vp_index,
            backend: Box::new(LibcRsiIoctlBackend),
        }
    }

    #[cfg(test)]
    fn with_backend(fd: RawFd, vp_index: u32, backend: Box<dyn RsiIoctlBackend>) -> Self {
        Self {
            fd,
            vp_index,
            backend,
        }
    }

    fn make_payload(&self, input: RsiInput) -> MshvRsiCall {
        MshvRsiCall {
            vp_index: self.vp_index,
            command: input.command.0.into(),
            args: input.args,
            results: [0; 7],
            return_code: 0,
        }
    }
}

impl RsiClient for KernelRsiClient {
    fn call(&self, input: RsiInput) -> Result<RsiOutput, RsiError> {
        let mut payload = self.make_payload(input);
        self.backend.call(self.fd, &mut payload).map_err(|_| {
            RsiError::RsiError(RsiReturnCode::ERROR_DEVICE)
        })?;

        Ok(RsiOutput {
            return_code: RsiReturnCode(payload.return_code),
            results: payload.results,
        })
    }
}

/// Resolved CCA realm configuration used by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealmConfig {
    /// Realm IPA width in bits.
    pub ipa_width: u8,
}

/// Errors from querying CCA realm configuration.
#[derive(Debug, Error)]
pub enum CcaQueryError {
    /// RSI REALM_CONFIG returned an error.
    #[error("RSI REALM_CONFIG failed: {0}")]
    Rsi(RsiError),
}

/// Query RSI REALM_CONFIG through the kernel RSI adapter.
pub fn query_realm_config(fd: RawFd, vp_index: u32) -> Result<RealmConfig, CcaQueryError> {
    let client = KernelRsiClient::new(fd, vp_index);
    let config = rsi::rsi_realm_config(&client).map_err(CcaQueryError::Rsi)?;

    Ok(RealmConfig {
        ipa_width: config.ipa_width,
    })
}

/// Memory visibility transition target for RSI IPA state changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpaVisibility {
    /// Transition range to host-shared state.
    Shared,
    /// Transition range to private realm state.
    Private,
}

/// Configuration for RSI IPA state transition batching.
#[derive(Debug, Clone, Copy)]
pub struct IpaTransitionConfig {
    /// Maximum number of 4K pages to include in one RSI_IPA_STATE_SET request.
    pub max_pages_per_call: u64,
}

impl Default for IpaTransitionConfig {
    fn default() -> Self {
        Self {
            max_pages_per_call: 512,
        }
    }
}

/// Errors returned by RSI IPA visibility transitions.
#[derive(Debug, Error)]
pub enum CcaIpaTransitionError {
    /// Invalid range or configuration was provided.
    #[error("invalid IPA transition input")]
    InvalidInput,
    /// RSI transition call failed.
    #[error("RSI IPA transition failed: {0}")]
    Rsi(RsiError),
    /// RSI made no forward progress while transitioning a range.
    #[error("RSI IPA transition made no forward progress")]
    NoProgress,
}

fn map_visibility(visibility: IpaVisibility) -> rsi::IpaState {
    match visibility {
        IpaVisibility::Shared => rsi::IpaState::Shared,
        IpaVisibility::Private => rsi::IpaState::Empty,
    }
}

fn transition_ipa_range(
    client: &dyn RsiClient,
    range: MemoryRange,
    visibility: IpaVisibility,
    cfg: IpaTransitionConfig,
) -> Result<(), CcaIpaTransitionError> {
    let page_size = 4096u64;
    let mut current = range.start();
    let top = range.end();
    let state = map_visibility(visibility);

    if cfg.max_pages_per_call == 0 || current >= top {
        return Err(CcaIpaTransitionError::InvalidInput);
    }

    let max_bytes = cfg
        .max_pages_per_call
        .checked_mul(page_size)
        .ok_or(CcaIpaTransitionError::InvalidInput)?;

    while current < top {
        let chunk_top = core::cmp::min(
            current
                .checked_add(max_bytes)
                .ok_or(CcaIpaTransitionError::InvalidInput)?,
            top,
        );

        let next = rsi::rsi_ipa_state_set(client, current, chunk_top, state, 0)
            .map_err(CcaIpaTransitionError::Rsi)?;
        if next <= current || next > chunk_top {
            return Err(CcaIpaTransitionError::NoProgress);
        }
        current = next;
    }

    Ok(())
}

/// Transition one or more IPA ranges to shared/private through RSI_IPA_STATE_SET.
pub fn transition_ipa_visibility(
    fd: RawFd,
    vp_index: u32,
    ranges: &[MemoryRange],
    visibility: IpaVisibility,
    cfg: IpaTransitionConfig,
) -> Result<(), CcaIpaTransitionError> {
    let client = KernelRsiClient::new(fd, vp_index);
    for &range in ranges {
        transition_ipa_range(&client, range, visibility, cfg)?;
    }
    Ok(())
}

#[cfg(test)]
fn transition_ipa_visibility_with_client(
    client: &dyn RsiClient,
    ranges: &[MemoryRange],
    visibility: IpaVisibility,
    cfg: IpaTransitionConfig,
) -> Result<(), CcaIpaTransitionError> {
    for &range in ranges {
        transition_ipa_range(client, range, visibility, cfg)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use rsi::RsiCommand;
    use std::collections::VecDeque;
    use std::sync::Arc;

    #[derive(Default)]
    struct MockBackend {
        captured: Arc<Mutex<Vec<MshvRsiCall>>>,
        result_code: i32,
        results: [u64; 7],
        fail: bool,
    }

    impl RsiIoctlBackend for MockBackend {
        fn call(&self, _fd: RawFd, payload: &mut MshvRsiCall) -> Result<(), nix::Error> {
            self.captured.lock().push(*payload);
            if self.fail {
                return Err(nix::Error::EINVAL);
            }

            payload.return_code = self.result_code;
            payload.results = self.results;
            Ok(())
        }
    }

    #[test]
    fn packs_rsi_input_into_ioctl_payload() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let backend = MockBackend {
            captured: captured.clone(),
            result_code: 0,
            results: [0; 7],
            fail: false,
        };
        let client = KernelRsiClient::with_backend(7, 42, Box::new(backend));

        let input = RsiInput::new(RsiCommand::VERSION).with_arg(0, 0xAA55).unwrap();
        let _ = client.call(input).unwrap();

        let calls = captured.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].vp_index, 42);
        assert_eq!(calls[0].command, RsiCommand::VERSION.0.into());
        assert_eq!(calls[0].args[0], 0xAA55);
    }

    #[test]
    fn unpacks_ioctl_results_into_rsi_output() {
        let backend = MockBackend {
            captured: Arc::new(Mutex::new(Vec::new())),
            result_code: RsiReturnCode::INCOMPLETE.0,
            results: [11, 22, 33, 44, 55, 66, 77],
            fail: false,
        };
        let client = KernelRsiClient::with_backend(3, 1, Box::new(backend));

        let output = client.call(RsiInput::new(RsiCommand::IPA_STATE_SET)).unwrap();
        assert_eq!(output.return_code, RsiReturnCode::INCOMPLETE);
        assert_eq!(output.results, [11, 22, 33, 44, 55, 66, 77]);
    }

    #[test]
    fn maps_ioctl_error_to_rsi_device_error() {
        let backend = MockBackend {
            captured: Arc::new(Mutex::new(Vec::new())),
            result_code: 0,
            results: [0; 7],
            fail: true,
        };
        let client = KernelRsiClient::with_backend(3, 1, Box::new(backend));

        let err = client.call(RsiInput::new(RsiCommand::VERSION)).unwrap_err();
        assert_eq!(err, RsiError::RsiError(RsiReturnCode::ERROR_DEVICE));
    }

    struct MockRsiClient {
        responses: Mutex<VecDeque<u64>>,
        calls: Mutex<Vec<(u64, u64, rsi::IpaState)>>,
    }

    impl MockRsiClient {
        fn new(responses: impl IntoIterator<Item = u64>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl RsiClient for MockRsiClient {
        fn call(&self, input: RsiInput) -> Result<RsiOutput, RsiError> {
            if input.command != RsiCommand::IPA_STATE_SET {
                return Err(RsiError::NotSupported);
            }

            let base = input.args[0];
            let top = input.args[1];
            let state = match input.args[2] {
                0 => rsi::IpaState::Empty,
                2 => rsi::IpaState::Shared,
                _ => return Err(RsiError::InvalidInput),
            };
            self.calls.lock().push((base, top, state));

            let next = self
                .responses
                .lock()
                .pop_front()
                .unwrap_or(top);

            Ok(RsiOutput {
                return_code: if next == top {
                    RsiReturnCode::SUCCESS
                } else {
                    RsiReturnCode::INCOMPLETE
                },
                results: [next, 0, 0, 0, 0, 0, 0],
            })
        }
    }

    #[test]
    fn ipa_transition_chunks_and_retries_until_complete() {
        let page = 4096u64;
        let start = 0x1000_0000;
        let end = start + (6 * page);
        let range = MemoryRange::new(start..end);

        let client = MockRsiClient::new([
            start + page,
            start + 2 * page,
            start + 3 * page,
            start + 4 * page,
            start + 5 * page,
            end,
        ]);

        transition_ipa_visibility_with_client(
            &client,
            &[range],
            IpaVisibility::Shared,
            IpaTransitionConfig {
                max_pages_per_call: 2,
            },
        )
        .unwrap();

        let calls = client.calls.lock();
        assert_eq!(calls.len(), 6);
        assert!(calls.iter().all(|(_, _, state)| *state == rsi::IpaState::Shared));
        assert_eq!(calls.first().unwrap().0, start);
        assert_eq!(calls.last().unwrap().1, end);
    }

    #[test]
    fn ipa_transition_rejects_non_progress() {
        let page = 4096u64;
        let start = 0x2000_0000;
        let end = start + (2 * page);
        let range = MemoryRange::new(start..end);

        let client = MockRsiClient::new([start]);
        let err = transition_ipa_visibility_with_client(
            &client,
            &[range],
            IpaVisibility::Private,
            IpaTransitionConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CcaIpaTransitionError::NoProgress));
    }
}

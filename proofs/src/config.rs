//! Per-proof policy for extended-domain polynomial storage.

use std::{
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Small circuits usually prove faster with heap-resident cosets.
pub const DEFAULT_COSET_SPILL_FLOOR_K: u32 = 18;

/// Controls the memory/disk trade-off while constructing a proof.
///
/// A policy belongs to one proof invocation; concurrent proofs may choose
/// different storage and spill directories without changing process state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverConfig {
    /// Keep proving-key columns in read-only mapped tempfiles after keygen or
    /// load.
    pub map_prover_key: bool,
    /// Spill extended-domain cosets to unnamed, mapped temporary files.
    pub spill_cosets: bool,
    /// Minimum circuit `k` at which spilling is enabled.
    pub coset_spill_floor_k: u32,
    /// Directory for spill files, or the operating system default.
    pub spill_dir: Option<PathBuf>,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self::heap()
    }
}

impl ProverConfig {
    /// Use the original heap-backed proving path.
    pub const fn heap() -> Self {
        Self {
            map_prover_key: false,
            spill_cosets: false,
            coset_spill_floor_k: DEFAULT_COSET_SPILL_FLOOR_K,
            spill_dir: None,
        }
    }

    /// Spill cosets at or above the default size floor.
    pub fn spilled() -> Self {
        Self {
            spill_cosets: true,
            ..Self::heap()
        }
    }

    /// Map the proving key while retaining ordinary heap-backed cosets.
    pub fn mapped_key() -> Self {
        Self {
            map_prover_key: true,
            ..Self::heap()
        }
    }

    /// Map the proving key and spill large extended-domain cosets.
    pub fn mapped_key_and_cosets() -> Self {
        Self {
            spill_cosets: true,
            ..Self::mapped_key()
        }
    }

    /// Whether the policy asks for coset spilling at `k`.
    pub const fn spills_cosets_at(&self, k: u32) -> bool {
        self.spill_cosets && k >= self.coset_spill_floor_k
    }

    /// Read process-wide settings once at the application boundary. Callers
    /// can pass this policy to the explicit keygen, load, and proof APIs.
    pub fn process() -> &'static Self {
        static PROCESS: OnceLock<ProverConfig> = OnceLock::new();
        PROCESS.get_or_init(|| Self {
            map_prover_key: matches!(
                std::env::var("MIDNIGHT_MAP_PK").as_deref(),
                Ok("1") | Ok("true")
            ),
            spill_cosets: matches!(
                std::env::var("MIDNIGHT_SPILL_COSETS").as_deref(),
                Ok("1") | Ok("true")
            ),
            coset_spill_floor_k: std::env::var("MIDNIGHT_SPILL_FLOOR_K")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_COSET_SPILL_FLOOR_K),
            spill_dir: std::env::var_os("MIDNIGHT_SPILL_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        })
    }
}

/// A cancellation request shared only by the caller and proofs holding its
/// clones.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// Create a token that has not been cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask a proof to stop at its next context checkpoint.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Memory policy and optional cancellation for one proof invocation.
#[derive(Clone, Debug, Default)]
pub struct ProverContext {
    /// Storage policy for extended-domain cosets.
    pub config: ProverConfig,
    /// Cancellation handle, if the caller wants to interrupt this proof.
    pub cancel: Option<CancelToken>,
}

impl ProverContext {
    /// Use a policy without cancellation.
    pub fn new(config: ProverConfig) -> Self {
        Self {
            config,
            cancel: None,
        }
    }

    /// Attach a request-owned cancellation token.
    pub fn with_cancel(mut self, token: CancelToken) -> Self {
        self.cancel = Some(token);
        self
    }

    /// Whether this invocation has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.as_ref().is_some_and(CancelToken::is_cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spill_gate_requires_switch_and_floor() {
        assert!(!ProverConfig::heap().spills_cosets_at(20));
        assert!(!ProverConfig::spilled().spills_cosets_at(17));
        assert!(ProverConfig::spilled().spills_cosets_at(18));
    }

    #[test]
    fn mapped_key_profiles_are_explicit() {
        assert!(!ProverConfig::heap().map_prover_key);
        assert!(ProverConfig::mapped_key().map_prover_key);
        assert!(!ProverConfig::mapped_key().spill_cosets);
        assert!(ProverConfig::mapped_key_and_cosets().map_prover_key);
        assert!(ProverConfig::mapped_key_and_cosets().spill_cosets);
    }
}

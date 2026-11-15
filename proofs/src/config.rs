//! Explicit request policy for the opt-in native proving storage paths.
//!
//! Default construction uses the released heap path. Callers choose native
//! storage per request; no environment variables or process-global flags are
//! consulted by this module.

use std::{io, path::PathBuf};

use crate::plonk::CosetStoragePolicy;
pub use crate::plonk::{CancelToken, ProverContext};

/// Default minimum `k` for extended-coset spilling.
pub const DEFAULT_COSET_SPILL_FLOOR_K: u32 = 18;

/// How a caller stores the proving key and derived cosets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverConfig {
    /// Load fixed proving-key columns into native mapped backing.
    pub map_prover_key: bool,
    /// Stream extended-domain cosets into mapped backing.
    pub spill_cosets: bool,
    /// Minimum circuit size at which requested coset spilling engages.
    pub coset_spill_floor_k: u32,
    /// Optional temporary-file volume for mapped key and coset storage.
    pub spill_dir: Option<PathBuf>,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self::heap()
    }
}

impl ProverConfig {
    /// Use the released in-memory proving behavior.
    pub fn heap() -> Self {
        Self {
            map_prover_key: false,
            spill_cosets: false,
            coset_spill_floor_k: DEFAULT_COSET_SPILL_FLOOR_K,
            spill_dir: None,
        }
    }

    /// Map the key while leaving cosets on the heap.
    pub fn mapped_key() -> Self {
        Self {
            map_prover_key: true,
            ..Self::heap()
        }
    }

    /// Map the key and spill cosets at or above the default floor.
    pub fn mapped_key_and_cosets() -> Self {
        Self {
            spill_cosets: true,
            ..Self::mapped_key()
        }
    }

    /// Whether this policy spills a circuit of size `k`.
    pub fn spills_cosets_at(&self, k: u32) -> bool {
        self.spill_cosets && k >= self.coset_spill_floor_k
    }

    /// Return an explicit error when native storage is requested on a build
    /// that cannot provide it. Heap policy works on every target.
    pub fn ensure_supported(&self) -> io::Result<()> {
        if self.map_prover_key && !cfg!(all(feature = "disk-spill", not(target_family = "wasm"))) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native proving storage requires non-Wasm disk-spill support",
            ));
        }
        self.coset_policy().ensure_supported()
    }

    pub(crate) fn coset_policy(&self) -> CosetStoragePolicy {
        if self.spill_cosets {
            CosetStoragePolicy::Spill {
                min_k: self.coset_spill_floor_k,
                dir: self.spill_dir.clone(),
            }
        } else {
            CosetStoragePolicy::Heap
        }
    }
}

impl From<CosetStoragePolicy> for ProverConfig {
    fn from(policy: CosetStoragePolicy) -> Self {
        match policy {
            CosetStoragePolicy::Heap => Self::heap(),
            CosetStoragePolicy::Spill { min_k, dir } => Self {
                spill_cosets: true,
                coset_spill_floor_k: min_k,
                spill_dir: dir,
                ..Self::heap()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_policy_is_explicit_and_floor_gated() {
        let mut policy = ProverConfig::mapped_key_and_cosets();
        assert!(!policy.spills_cosets_at(17));
        assert!(policy.spills_cosets_at(18));
        policy.coset_spill_floor_k = 20;
        assert!(!policy.spills_cosets_at(18));
        assert!(policy.spills_cosets_at(20));
        assert!(!ProverConfig::heap().spills_cosets_at(20));
    }

    #[test]
    fn unsupported_native_policy_fails_closed() {
        assert!(ProverConfig::heap().ensure_supported().is_ok());
        let result = ProverConfig::mapped_key().ensure_supported();
        if cfg!(all(feature = "disk-spill", not(target_family = "wasm"))) {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
    }
}

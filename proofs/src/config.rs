//! Per-proof policy for extended-domain polynomial storage.

use std::{path::PathBuf, sync::OnceLock};

/// Small circuits usually prove faster with heap-resident cosets.
pub const DEFAULT_COSET_SPILL_FLOOR_K: u32 = 18;

/// Controls the memory/disk trade-off while constructing a proof.
///
/// A policy belongs to one proof invocation; concurrent proofs may choose
/// different storage and spill directories without changing process state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverConfig {
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

    /// Whether the policy asks for coset spilling at `k`.
    pub const fn spills_cosets_at(&self, k: u32) -> bool {
        self.spill_cosets && k >= self.coset_spill_floor_k
    }

    /// Read legacy process-wide settings once at the application boundary.
    /// Explicit callers should pass a policy to `create_proof_with` instead.
    pub fn process() -> &'static Self {
        static PROCESS: OnceLock<ProverConfig> = OnceLock::new();
        PROCESS.get_or_init(|| Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spill_gate_requires_switch_and_floor() {
        assert!(!ProverConfig::heap().spills_cosets_at(20));
        assert!(!ProverConfig::spilled().spills_cosets_at(17));
        assert!(ProverConfig::spilled().spills_cosets_at(18));
    }
}

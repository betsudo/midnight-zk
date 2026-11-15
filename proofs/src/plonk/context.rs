//! Request-local execution controls for the opt-in prover API.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use super::{CosetStoragePolicy, ProveWithPolicyError};

/// A cancellation handle shared only with its clones.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// Construct an independent, initially active handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop proofs that use this token at their next phase boundary.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Return whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Per-proof storage and cancellation controls. The default is the released
/// heap behavior with no cancellation token.
#[derive(Clone, Debug, Default)]
pub struct ProverContext {
    pub(crate) cosets: CosetStoragePolicy,
    pub(crate) cancel: Option<CancelToken>,
}

impl ProverContext {
    /// Select a coset policy for this proof.
    pub fn new(cosets: CosetStoragePolicy) -> Self {
        Self {
            cosets,
            cancel: None,
        }
    }

    /// Attach a request-scoped cancellation handle.
    pub fn with_cancel(mut self, token: CancelToken) -> Self {
        self.cancel = Some(token);
        self
    }

    pub(crate) fn checkpoint(&self, phase: &'static str) -> Result<(), ProveWithPolicyError> {
        if self.cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
            return Err(ProveWithPolicyError::Cancelled { phase });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_token_is_isolated_from_another_request() {
        let first = CancelToken::new();
        let second = CancelToken::new();
        let first_proof = ProverContext::default().with_cancel(first.clone());
        let second_proof = ProverContext::default().with_cancel(second);

        first.cancel();
        assert!(matches!(
            first_proof.checkpoint("trace"),
            Err(ProveWithPolicyError::Cancelled { phase: "trace" })
        ));
        assert!(second_proof.checkpoint("trace").is_ok());
        assert!(ProverContext::default().checkpoint("trace").is_ok());
    }
}

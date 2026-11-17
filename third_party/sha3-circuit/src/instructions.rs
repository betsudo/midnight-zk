use std::fmt::Debug;

use ff::PrimeField;
use midnight_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::Error,
};

use crate::constants::KECCAK_ABSORB_BYTES;

/// The set of circuit instructions for the keccak-f[1600] permutation.
pub trait Keccackf1600Instructions<F: PrimeField>: Chip<F> + Clone + Debug {
    /// Variable representing the (assigned) keccakf internal state in circuit.
    type State: Clone + Debug;

    /// Variable representing the (assigned) keccakf 64-bit lane in circuit.
    type Lane: Clone + Debug;

    /// Variable representing the (assigned) absorbed block in circuit.
    /// It should be convertible into a array of [`Cell`] representing absorbed
    /// bytes
    type AbsorbedBlock: Clone + Debug + Into<Vec<Self::AssignedByte>>;

    /// Variable representing the (assigned) squeezed digest in circuit.
    type Digest: Clone + Debug;

    /// Byte type
    type UnassignedByte: Clone + Debug + From<u8>;

    /// Assigned byte type. This should convert to an AssignedCell representing
    /// an unassignedbyte
    type AssignedByte: Clone + Debug + Into<AssignedCell<Self::UnassignedByte, F>>;

    /// The minimum log of number of rows needed to digest a message. It takes
    /// the message's byte length as input
    fn min_k(len: usize) -> u32;

    /// Assigns bytes to a message block to be absorbed
    fn assign_message_block(
        &self,
        layouter: &mut impl Layouter<F>,
        bytes: &[Value<Self::UnassignedByte>; KECCAK_ABSORB_BYTES],
    ) -> Result<Self::AbsorbedBlock, Error>;

    /// Initialize the keccak state.
    fn initialize(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error>;

    /// Initialize state from a [`Keccackf1600Instructions::AbsorbedBlock`].
    /// This should usually be more efficient than initializing and
    /// absorbing a block.
    fn initialize_and_absorb(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Self::AbsorbedBlock,
    ) -> Result<Self::State, Error> {
        let initial_state = self.initialize(layouter)?;
        self.absorb(layouter, &initial_state, block)
    }

    /// Given as input a keccak state, it computes the state
    /// after applying the full keccak-f permutation.
    fn keccakf(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
    ) -> Result<Self::State, Error>;

    /// Given as input a keccak state, it computes the state
    /// after absorbing a [`Keccackf1600Instructions::AbsorbedBlock`].
    fn absorb(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
        ms: &Self::AbsorbedBlock,
    ) -> Result<Self::State, Error>;

    /// Same as [`Keccackf1600Instructions::keccakf`] but also optionally
    /// absorbs a message *after* the permutation is applied.
    ///
    /// The reason for having this function is that it is normally more
    /// efficient in-circuit to do together the permutation and absorbing.
    fn keccakf_and_absorb(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
        ms: Option<&Self::AbsorbedBlock>,
    ) -> Result<Self::State, Error> {
        // permute
        let state_after_permutation = self.keccakf(layouter, state)?;

        // absorb
        self.absorb(layouter, &state_after_permutation, ms.unwrap())
    }

    /// Given a keccak state, it squeezes 32 bytes *without applying a
    /// permutation*. To squeeze more bytes a permutation has to be done
    /// manually.
    fn squeeze(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
    ) -> Result<Self::Digest, Error>;
}

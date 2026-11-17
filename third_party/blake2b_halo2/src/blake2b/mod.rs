//! A chip defining a Blake2b hash invocation. This interface works with in/out consisting of
//! AssignedNative. The algorithm expects its values to be in the range of a Byte, and will fail if
//! they're not.
//!
//! The chip relies on a set of basic instructions, implemented as a trait called
//! [Blake2bInstructions]. There is currently one implementation of the instruction set:
//! * [Blake2bChip] This chip uses a lookup table of size `2**16`. This means
//!   that all circuits instantiating this chip will be at least `2**17` rows,
//!   as we need to padd the circuit to provide ZK. This chip achieves a Blake2b
//!   digest in 2469 rows.

/// This is the trait that contains most of the behaviour of the blake2b chips.
pub(crate) mod blake2b_instructions;

/// Basic definitions and constants for the blake2b chip.
pub(crate) mod utils;

/// These are the separated optimizations.
pub mod blake2b_chip;

/// Number of advice columns required by the chip.
pub const NB_BLAKE2B_ADVICE_COLS: usize = 9;

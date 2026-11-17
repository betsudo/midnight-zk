use std::marker::PhantomData;

use ff::PrimeField;
use midnight_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::Error,
};

use crate::{
    constants::KECCAK_ABSORB_BYTES, instructions::Keccackf1600Instructions, packed_chip::PackedChip,
};

#[derive(Debug, Clone, Copy)]
/// Enum that represents the two supported hash modes. These are:
///
/// - the Sha3_256 hash as standardized by NIST,
/// - the Keccak256 hash as submitted by the Keccak team and used by Ethereum.
///
/// These only differ slightly in the implementation of message-padding.
///
/// The two corresponding references can be found in
///
/// - [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
/// - [The Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf)
enum HashMode {
    Sha3_256,
    Keccak256,
}

/// A gadget that computs a SHA3 digest in either Sha3_256 or Keccak256 mode.
#[derive(Debug)]
struct Sha3Family<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    chip: KeccakF,
    mode: HashMode,
    phantom: PhantomData<F>,
}

impl<F, KeccakF> Sha3Family<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    /// Helper function that takes as input the assigned padding bytes
    /// and constraints the padding bytes to have the right (constant) value.
    fn constrain_padding(
        &self,
        layouter: &mut impl Layouter<F>,
        assigned_padding_bytes: &[KeccakF::AssignedByte],
    ) -> Result<(), Error> {
        let q = assigned_padding_bytes.len();

        layouter.assign_region(
            || "constrain padding region",
            |mut region| {
                if q == 1 {
                    // one missing byte
                    let last_byte = assigned_padding_bytes.last().unwrap();
                    let last_byte: AssignedCell<KeccakF::UnassignedByte, F> =
                        last_byte.clone().into();
                    match self.mode {
                        HashMode::Sha3_256 => {
                            region.constrain_constant(last_byte.cell(), F::from(0x86))
                        }
                        HashMode::Keccak256 => {
                            region.constrain_constant(last_byte.cell(), F::from(0x81))
                        }
                    }
                } else {
                    assigned_padding_bytes.iter().rev().take(q).enumerate().try_for_each(
                        |(i, assigned_byte)| {
                            let assigned_byte: AssignedCell<KeccakF::UnassignedByte, F> =
                                assigned_byte.clone().into();
                            if i == 0 {
                                // last padding byte
                                region.constrain_constant(assigned_byte.cell(), F::from(0x80))
                            } else if i == q - 1 {
                                match self.mode {
                                    // first padding byte
                                    HashMode::Sha3_256 => region
                                        .constrain_constant(assigned_byte.cell(), F::from(0x06)),
                                    HashMode::Keccak256 => region
                                        .constrain_constant(assigned_byte.cell(), F::from(0x01)),
                                }
                            } else {
                                // rest padding bytes
                                region.constrain_constant(assigned_byte.cell(), F::from(0x00))
                            }
                        },
                    )
                }
            },
        )
    }

    fn new(chip: KeccakF, mode: HashMode) -> Self {
        Self {
            chip,
            mode,
            phantom: PhantomData,
        }
    }

    /// Digests the `hash_input` in circuit and returns the assigned output.
    fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_input: &[Value<u8>],
    ) -> Result<(Vec<KeccakF::AssignedByte>, KeccakF::Digest), Error> {
        let input_len = hash_input.len();

        // pad the input
        let mut input = hash_input
            .iter()
            .map(|b| b.map(<KeccakF::UnassignedByte>::from))
            .collect::<Vec<_>>();

        let q = KECCAK_ABSORB_BYTES - input.len() % (KECCAK_ABSORB_BYTES);
        if q == 1 {
            // one missing byte -> pad with
            // - 0x86 for sha3
            // - 0x81 for keccak
            match self.mode {
                HashMode::Sha3_256 => input.push(Value::known(0x86.into())),
                HashMode::Keccak256 => input.push(Value::known(0x81.into())),
            }
        } else {
            // more than one missing bytes -> pad with
            // - 0x06, 0x00, ..., 0x00, 0x80 for sha3
            // - 0x01, 0x00, ..., 0x00, 0x80 for keccak
            //
            // The corresponding references are here:
            // - [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
            // - [The Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf)
            match self.mode {
                HashMode::Sha3_256 => input.push(Value::known(0x06.into())),
                HashMode::Keccak256 => input.push(Value::known(0x01.into())),
            }
            input.extend_from_slice(vec![Value::known(0x00.into()); q - 2].as_slice());
            input.push(Value::known(0x80.into()));
        }

        // assign the blocks
        let blocks: Vec<[_; KECCAK_ABSORB_BYTES]> = input
            .chunks(KECCAK_ABSORB_BYTES)
            .map(|chunk| chunk.to_vec().try_into().unwrap())
            .collect();

        let assigned_blocks = blocks
            .iter()
            .map(|bytes| self.chip.assign_message_block(layouter, bytes))
            .collect::<Result<Vec<_>, _>>()?;

        let assigned_bytes: Vec<KeccakF::AssignedByte> = assigned_blocks
            .iter()
            .flat_map(|block| block.clone().into())
            .collect::<Vec<_>>();

        // apply the padding constraints
        self.constrain_padding(layouter, &assigned_bytes[input_len..])?;

        // initialize the state from the first block
        let initial_state = self.chip.initialize_and_absorb(layouter, &assigned_blocks[0])?;

        // permute and absorb for each remaining block
        let state = assigned_blocks[1..].iter().try_fold(initial_state, |old_state, block| {
            self.chip.keccakf_and_absorb(layouter, &old_state, Some(block))
        })?;

        // do the final permutation
        let final_state = self.chip.keccakf(layouter, &state)?;

        let input = assigned_bytes[0..input_len].to_vec();
        // squeeze to get the result
        let output = self.chip.squeeze(layouter, &final_state)?;
        Ok((input, output))
    }
}

/// A wrapper gadget that computs a SHA3_256 digest.
#[derive(Debug, Clone)]
pub struct Sha3_256<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    chip: KeccakF,
    phantom: PhantomData<F>,
}

impl<F, KeccakF> Chip<F> for Sha3_256<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    type Config = <KeccakF as Chip<F>>::Config;
    type Loaded = <KeccakF as Chip<F>>::Loaded;
    fn config(&self) -> &Self::Config {
        self.chip.config()
    }
    fn loaded(&self) -> &Self::Loaded {
        self.chip.loaded()
    }
}

impl<F, KeccakF> Sha3_256<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    /// Generates a new chip from the packed chip.
    pub fn new(chip: KeccakF) -> Self {
        Self {
            chip,
            phantom: PhantomData,
        }
    }

    /// Digests the `hash_input` in circuit and returns the assigned output.
    pub fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_input: &[Value<u8>],
    ) -> Result<(Vec<KeccakF::AssignedByte>, KeccakF::Digest), Error> {
        let hasher = Sha3Family::new(self.chip.clone(), HashMode::Sha3_256);
        hasher.digest(layouter, hash_input)
    }
}

/// A wrapper gadget that computs a Keccak_256 digest.
#[derive(Debug, Clone)]
pub struct Keccak256<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    chip: KeccakF,
    phantom: PhantomData<F>,
}

impl<F, KeccakF> Chip<F> for Keccak256<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    type Config = <KeccakF as Chip<F>>::Config;
    type Loaded = <KeccakF as Chip<F>>::Loaded;
    fn config(&self) -> &Self::Config {
        self.chip.config()
    }
    fn loaded(&self) -> &Self::Loaded {
        self.chip.loaded()
    }
}

impl<F, KeccakF> Keccak256<F, KeccakF>
where
    F: PrimeField,
    KeccakF: Keccackf1600Instructions<F>,
{
    /// Generates a new chip from the packed chip.
    pub fn new(chip: KeccakF) -> Self {
        Self {
            chip,
            phantom: PhantomData,
        }
    }

    /// Digests the `hash_input` in circuit. Takes the input in unassigned form,
    /// and returns both the assigned input and the assigned output (digest).
    pub fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_input: &[Value<u8>],
    ) -> Result<(Vec<KeccakF::AssignedByte>, KeccakF::Digest), Error> {
        let hasher = Sha3Family::new(self.chip.clone(), HashMode::Keccak256);
        hasher.digest(layouter, hash_input)
    }
}

// The load function only needs to be defined for either Keccak or Sha, since
// they share the same tables.
impl<F: PrimeField> Keccak256<F, PackedChip<F>> {
    /// Loads the tables of the underlying packed chip.
    pub fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.chip.load_table(layouter)
    }
}

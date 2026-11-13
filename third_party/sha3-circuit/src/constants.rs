//! Various constants used in the keccak specs

pub(crate) const KECCAK_BYTES_PER_LANE: usize = 8;

/// The size of a Keccak lane
pub(crate) const KECCAK_LANE_SIZE: usize = 64;

/// The width of Keccak state
pub(crate) const KECCAK_WIDTH: usize = 5;

/// The number of lanes of a Keccak state
pub(crate) const KECCAK_NUM_LANES: usize = KECCAK_WIDTH * KECCAK_WIDTH;

/// The number of rounds of Keccak
pub(crate) const KECCAK_NUM_ROUNDS: usize = 24;

/// The number of lanes absorbed before a Keccak-f application
pub(crate) const KECCAK_ABSORB_LANES: usize = 17;

/// The number of absorbed bytes per round
pub(crate) const KECCAK_ABSORB_BYTES: usize = KECCAK_ABSORB_LANES * KECCAK_BYTES_PER_LANE;

/// The number of squeezed bytes
pub const KECCAK_SQUEEZE_BYTES: usize = 32;

/// The Keccak round constants
pub(crate) const ROUND_CST: [u64; KECCAK_NUM_ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotations for the rho operation
pub(crate) const RHO_ROTATAIONS: [[usize; KECCAK_WIDTH]; KECCAK_WIDTH] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

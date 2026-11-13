//! Owned or read-only mapped storage for affine KZG bases.
//!
//! A mapped slice is only constructed from a private companion produced by
//! this crate. The caller must keep its backing file immutable while mapped.

use std::ops::Deref;
#[cfg(feature = "mmap")]
use std::sync::Arc;

#[cfg(feature = "mmap")]
use memmap2::Mmap;

/// Types whose in-memory bytes can be written and read without padding or
/// validity invariants. This sealed contract is stronger than serialization.
///
/// # Safety
/// Implementors must be plain initialized bytes with no padding or Rust
/// validity invariants. The trait is sealed to the curve layout audited here.
#[cfg(feature = "mmap")]
#[allow(unsafe_code)]
pub unsafe trait PlainBytes: sealed::Sealed + Copy + 'static {}

#[cfg(feature = "mmap")]
mod sealed {
    pub trait Sealed {}
}

#[cfg(feature = "mmap")]
impl sealed::Sealed for midnight_curves::G1Affine {}

// SAFETY: G1Affine is repr(transparent) over blst_p1_affine, which contains
// exactly two blst_fp values, each six u64 limbs. The type has no Rust niches
// or padding; all bit patterns inhabit it, even if they are not curve points.
#[cfg(feature = "mmap")]
#[allow(unsafe_code)]
unsafe impl PlainBytes for midnight_curves::G1Affine {}

#[cfg(feature = "mmap")]
const _: () = {
    assert!(std::mem::size_of::<midnight_curves::G1Affine>() == 96);
    assert!(std::mem::align_of::<midnight_curves::G1Affine>() == std::mem::align_of::<u64>());
};

/// Storage for one KZG basis. Mapped values borrow immutable bytes from an
/// Arc held by this value, so cloning a mapped basis does not copy points.
pub(crate) enum BasesStorage<C: 'static> {
    Owned(Vec<C>),
    #[cfg(feature = "mmap")]
    Mapped {
        mmap: Arc<Mmap>,
        offset: usize,
        len: usize,
    },
}

impl<C: 'static> BasesStorage<C> {
    pub(crate) fn owned(points: Vec<C>) -> Self {
        Self::Owned(points)
    }

    /// # Safety
    /// The byte range must be in `mmap`, aligned for `C`, and hold `len`
    /// initialized `C` values. The backing file must remain immutable for the
    /// lifetime of this mapping. Only `PlainBytes` types are accepted.
    #[cfg(feature = "mmap")]
    #[allow(unsafe_code)]
    pub(crate) unsafe fn mapped(mmap: Arc<Mmap>, offset: usize, len: usize) -> Self
    where
        C: PlainBytes,
    {
        Self::Mapped { mmap, offset, len }
    }

    pub(crate) fn truncate_into_owned(&mut self, n: usize)
    where
        C: Clone,
    {
        match self {
            Self::Owned(points) => points.truncate(n),
            #[cfg(feature = "mmap")]
            Self::Mapped { .. } => *self = Self::Owned(self[..n].to_vec()),
        }
    }

    #[cfg(all(test, feature = "mmap"))]
    pub(crate) fn is_mapped(&self) -> bool {
        matches!(self, Self::Mapped { .. })
    }
}

impl<C: 'static> Deref for BasesStorage<C> {
    type Target = [C];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(points) => points,
            // SAFETY: `mapped` requires a checked, aligned in-range block and
            // immutable backing. This Arc keeps the mapping alive for the borrow.
            #[cfg(feature = "mmap")]
            #[allow(unsafe_code)]
            Self::Mapped { mmap, offset, len } => unsafe {
                std::slice::from_raw_parts(mmap.as_ptr().add(*offset).cast::<C>(), *len)
            },
        }
    }
}

impl<C: Clone + 'static> Clone for BasesStorage<C> {
    fn clone(&self) -> Self {
        match self {
            Self::Owned(points) => Self::Owned(points.clone()),
            #[cfg(feature = "mmap")]
            Self::Mapped { mmap, offset, len } => Self::Mapped {
                mmap: Arc::clone(mmap),
                offset: *offset,
                len: *len,
            },
        }
    }
}

impl<C: std::fmt::Debug + 'static> std::fmt::Debug for BasesStorage<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasesStorage")
            .field("mapped", &{
                #[cfg(feature = "mmap")]
                {
                    matches!(self, Self::Mapped { .. })
                }
                #[cfg(not(feature = "mmap"))]
                {
                    false
                }
            })
            .field("len", &self.len())
            .finish()
    }
}

impl<C: PartialEq + 'static> PartialEq for BasesStorage<C> {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl<C: Eq + 'static> Eq for BasesStorage<C> {}

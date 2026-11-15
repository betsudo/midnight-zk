// This file is part of midnight-zk.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: MIT OR Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Native, read-only mapped storage for proving-key polynomial columns.
//!
//! The mapping owns live field values through checked offsets and lengths.
//! Files are anonymous temporaries with physical backing reserved before mmap,
//! so a full disk yields an I/O error rather than a later page-fault SIGBUS.
//!
//! This module is only compiled for native builds with `disk-spill` enabled.

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
use std::io::Write;
use std::{io, marker::PhantomData, sync::Arc};

use crate::poly::{polynomial_views, Polynomial, PolynomialRead, PolynomialView};

/// One polynomial backed by a read-only mmap. Offsets are stored instead of
/// raw pointers, so moving or cloning this value cannot invalidate anything.
#[derive(Clone)]
struct MappedPolynomial<F, B> {
    mmap: Arc<memmap2::Mmap>,
    offset: usize,
    len: usize,
    _marker: PhantomData<(F, B)>,
}

impl<F, B> PolynomialRead<F> for MappedPolynomial<F, B> {
    type Basis = B;

    fn values(&self) -> &[F] {
        // SAFETY: `spill_iter_to_disk` sizes and aligns the mapping, writes a
        // live `F` to every element with `ptr::write`, and constructs offsets
        // wholly inside it. The Arc keeps the mapping alive and read-only.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts(self.mmap.as_ptr().add(self.offset) as *const F, self.len)
        }
    }
}

/// Read-only batch of polynomials backed by a mapped tempfile.
///
/// The struct holds mapped polynomial descriptors (`Arc<Mmap>` + offset +
/// length). The file descriptor used to create the mapping is closed before
/// this value is returned; the tempfile itself is unnamed.
///
/// `Sync`/`Send`: the descriptors are read-only; the compiler derives these
/// traits from `F`, `B`, and `Mmap`.
pub(crate) struct MmappedPolys<F, B> {
    polys: Vec<MappedPolynomial<F, B>>,
    mmap_bytes: usize,
}

impl<F, B> std::fmt::Debug for MmappedPolys<F, B> {
    // Custom Debug so callers that hold `MmappedPolys` as a field of
    // a `derive(Debug)` struct compile. We deliberately do NOT print
    // the polynomial values — they live in mmap pages, printing them
    // would force the OS to read the entire file into RAM.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmappedPolys")
            .field("n_polys", &self.polys.len())
            .field("mmap_bytes", &self.mmap_bytes)
            .finish()
    }
}

impl<F, B> MmappedPolys<F, B> {
    /// Borrow in the same concrete representation used for owned polynomials.
    pub(crate) fn views(&self) -> Vec<PolynomialView<'_, F, B>> {
        polynomial_views(&self.polys)
    }
}

/// Open an anonymous temporary file in the caller-selected directory.
fn make_tempfile(spill_dir: Option<&std::path::Path>) -> io::Result<std::fs::File> {
    // The error names the operation and the directory. Without that a caller
    // sees "No such file or directory" for a file that was never meant to
    // exist, and a proof server turns a misconfigured spill volume into a
    // client error blaming the request.
    match spill_dir {
        Some(dir) => tempfile::tempfile_in(dir).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("create spill temp file in {}: {e}", dir.display()),
            )
        }),
        None => tempfile::tempfile().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("create spill temp file in the OS temp dir: {e}"),
            )
        }),
    }
}

/// Whether a preallocation error means "this filesystem cannot preallocate"
/// rather than "there is no room".
///
/// `posix_fallocate` and `F_PREALLOCATE` are not universally implemented:
/// musl, ZFS, NFS and many FUSE filesystems reject them outright. Treating
/// that as fatal made the whole key load fail on hosts with plenty of free
/// space — a portability failure reported as a resource failure. Out of space
/// is different in kind and still fails: falling back there would write the
/// zero-fill until the volume filled, which is the SIGBUS this function
/// exists to prevent, only later.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn preallocation_unsupported(errno: i32) -> bool {
    matches!(
        errno,
        libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL | libc::ENOTTY | libc::EPERM
    )
}

/// Write the whole file out in zeroed blocks.
///
/// Portable and intentionally slower: every block is written, so an allocation
/// failure surfaces as an `io::Error` here rather than as a SIGBUS when the
/// mapping is later faulted in. This is the only path on platforms without a
/// preallocation syscall, and the fallback on platforms whose filesystem
/// refuses one.
fn zero_fill_spill_file(file: &mut std::fs::File, total_bytes: usize) -> io::Result<()> {
    use io::Write as _;

    // A `static`, not a `const`: a const of this size is materialised at each
    // use site (clippy's `large_const_arrays`), and one shared zero page-run is
    // exactly what a zero-fill wants.
    static ZERO_BLOCK: [u8; 1024 * 1024] = [0; 1024 * 1024];
    file.set_len(0)?;
    let mut remaining = total_bytes;
    while remaining != 0 {
        let n = remaining.min(ZERO_BLOCK.len());
        file.write_all(&ZERO_BLOCK[..n])?;
        remaining -= n;
    }
    file.flush()?;
    Ok(())
}

/// Ensure the spill has real backing store before a writable mapping can
/// fault pages in. Merely extending the file can create a sparse file; on a
/// full volume, writing that mapping may then terminate the process with
/// SIGBUS instead of returning an `io::Error`.
fn reserve_spill_file(file: &mut std::fs::File, total_bytes: usize) -> io::Result<()> {
    let file_len = u64::try_from(total_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "spill is too large"))?;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;

        let allocation_len = libc::off_t::try_from(total_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "spill is too large for off_t")
        })?;
        // SAFETY: `file` owns a valid descriptor and the offset/length are
        // checked representations. `posix_fallocate` does not access Rust
        // memory and returns an errno value directly.
        #[allow(unsafe_code)]
        let status = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, allocation_len) };
        if status != 0 {
            if preallocation_unsupported(status) {
                tracing::debug!(
                    errno = status,
                    "posix_fallocate is unsupported on this filesystem; zero-filling the spill"
                );
                return zero_fill_spill_file(file, total_bytes);
            }
            return Err(io::Error::from_raw_os_error(status));
        }
        file.set_len(file_len)?;
        Ok(())
    }

    #[cfg(target_vendor = "apple")]
    {
        use std::os::fd::AsRawFd;

        let allocation_len = libc::off_t::try_from(total_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "spill is too large for off_t")
        })?;
        let mut store = libc::fstore_t {
            // Require the contiguous attempt to be all-or-nothing. APFS may
            // otherwise report success after reserving only the largest
            // contiguous extent, which is insufficient for SIGBUS safety.
            fst_flags: libc::F_ALLOCATECONTIG | libc::F_ALLOCATEALL,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: allocation_len,
            fst_bytesalloc: 0,
        };
        // Prefer one contiguous allocation, then accept any complete physical
        // allocation. Both attempts are all-or-nothing.
        // SAFETY: `store` is a valid writable `fstore_t` for the duration of
        // both calls and `file` owns a valid descriptor.
        #[allow(unsafe_code)]
        let mut status = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
        if status == -1 {
            store.fst_flags = libc::F_ALLOCATEALL;
            #[allow(unsafe_code)]
            {
                status = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
            }
        }
        if status == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error().is_some_and(preallocation_unsupported) {
                tracing::debug!(
                    errno = err.raw_os_error(),
                    "F_PREALLOCATE is unsupported on this filesystem; zero-filling the spill"
                );
                return zero_fill_spill_file(file, total_bytes);
            }
            return Err(err);
        }
        if store.fst_bytesalloc < allocation_len {
            // A short reservation is a space problem, not a support problem:
            // both `F_PREALLOCATE` attempts above are all-or-nothing, so
            // reaching here means the volume could not give us the extents.
            // Zero-filling would only discover the same shortage later, from
            // inside a mapping.
            return Err(io::Error::other(
                "filesystem did not reserve the complete spill",
            ));
        }
        file.set_len(file_len)?;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        let _ = file_len;
        zero_fill_spill_file(file, total_bytes)
    }
}

/// Move each element of `polys` into a mutable file mapping, make the mapping
/// read-only, and return typed views over it.
///
/// The iterator MUST yield exactly `n_polys` values, each with
/// `values.len() == n_per_poly`. These invariants let the read-back
/// compute the i-th polynomial's offset as `i * n_per_poly` without
/// per-element headers; both are checked in release builds.
///
/// Peak transient heap stays at ~1 polynomial during the write — the
/// iterator yields owned `Polynomial<F, B>` values and each is
/// dropped immediately after its elements are copied into the mapping.
/// Constructing live values in the mapping avoids both allocator-forged
/// `Vec`s and assumptions about padding or a stable serialized layout.
///
/// # Errors
///
/// Returns an `io::Error` for invalid sizes or from tempfile/mmap operations.
pub(crate) fn spill_iter_to_disk<F, B, I>(
    spill_dir: Option<&std::path::Path>,
    polys: I,
    n_polys: usize,
    n_per_poly: usize,
) -> io::Result<MmappedPolys<F, B>>
where
    F: Copy,
    I: IntoIterator<Item = Polynomial<F, B>>,
{
    let elem_size = std::mem::size_of::<F>();
    if elem_size == 0 || n_per_poly == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spill requires non-empty rows of non-zero-sized elements",
        ));
    }

    let mut iter = polys.into_iter();
    let total_elems = n_polys.checked_mul(n_per_poly).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "spill element count overflows")
    })?;
    let total_bytes = total_elems
        .checked_mul(elem_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "spill byte count overflows"))?;
    let mut tmp = make_tempfile(spill_dir)?;

    if total_bytes == 0 {
        if iter.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill iterator yielded more polynomials than promised",
            ));
        }
        return Ok(MmappedPolys {
            polys: Vec::new(),
            mmap_bytes: 0,
        });
    }

    reserve_spill_file(&mut tmp, total_bytes)?;
    // SAFETY: the file is exclusively owned and has exactly `total_bytes`.
    #[allow(unsafe_code)]
    let mut mmap = unsafe { memmap2::MmapOptions::new().len(total_bytes).map_mut(&tmp)? };
    let base_ptr = mmap.as_mut_ptr() as *mut F;
    if (base_ptr as usize) % std::mem::align_of::<F>() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spill mapping is misaligned for polynomial elements",
        ));
    }

    let mut written_polys = 0usize;
    for (poly_index, poly) in iter.by_ref().enumerate() {
        // The declared count is checked on both sides of the loop. Reject
        // overproduction before pointer arithmetic and underproduction below.
        if poly_index >= n_polys {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill iterator yielded more polynomials than promised",
            ));
        }
        if poly.values.len() != n_per_poly {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "spill_iter_to_disk: polynomial size mismatch (got {}, expected {})",
                    poly.values.len(),
                    n_per_poly
                ),
            ));
        }
        let start = poly_index * n_per_poly;
        for (index, value) in poly.values.iter().copied().enumerate() {
            // SAFETY: the checked declared count fixed the mapping length; both
            // indices are checked above. `F: Copy` has no destructor, and this
            // writes a live value instead of reinterpreting serialized bytes.
            #[allow(unsafe_code)]
            unsafe {
                base_ptr.add(start + index).write(value);
            }
        }
        written_polys += 1;
    }
    if written_polys != n_polys {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spill iterator yielded fewer polynomials than promised",
        ));
    }

    mmap.flush()?;
    let mmap_arc = Arc::new(mmap.make_read_only()?);
    #[cfg(feature = "bench-internal")]
    if matches!(
        std::env::var("MIDNIGHT_BENCH_TRACE_SPILL_BYTES").as_deref(),
        Ok("1") | Ok("true")
    ) {
        eprintln!("Midnight spill file: bytes={total_bytes}");
    }
    let polys_view = (0..n_polys)
        .map(|index| MappedPolynomial {
            mmap: Arc::clone(&mmap_arc),
            offset: index * n_per_poly * elem_size,
            len: n_per_poly,
            _marker: PhantomData,
        })
        .collect();

    Ok(MmappedPolys {
        polys: polys_view,
        mmap_bytes: total_bytes,
    })
}

/// Convenience: spill a `Vec<Polynomial<F, B>>` (consuming it).
///
/// Equivalent to `spill_iter_to_disk(polys.into_iter(), polys.len(),
/// n_per_poly)`. Draining drops each polynomial's value buffer after it is
/// copied; the small descriptor `Vec` retains its allocation until the call
/// returns.
// Proving-key integration consumes this helper.
pub(crate) fn spill_vec_to_disk<F, B>(
    spill_dir: Option<&std::path::Path>,
    mut polys: Vec<Polynomial<F, B>>,
    n_per_poly: usize,
) -> io::Result<MmappedPolys<F, B>>
where
    F: Copy,
{
    let n_polys = polys.len();
    spill_iter_to_disk(spill_dir, polys.drain(..), n_polys, n_per_poly)
}

/// Transform coefficient views one at a time into mapped extended cosets.
/// The source polynomials remain owned by the caller; only one transformed
/// polynomial is resident on the heap during the spill.
pub(crate) fn spill_with_transform<F, P, T>(
    spill_dir: Option<&std::path::Path>,
    inputs: &[P],
    mut transform: T,
) -> io::Result<MmappedPolys<F, crate::poly::ExtendedLagrangeCoeff>>
where
    F: Copy,
    P: PolynomialRead<F, Basis = crate::poly::Coeff>,
    T: for<'a> FnMut(
        PolynomialView<'a, F, crate::poly::Coeff>,
    ) -> Polynomial<F, crate::poly::ExtendedLagrangeCoeff>,
{
    let (first, rest) = inputs.split_first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot spill an empty coset batch",
        )
    })?;
    let first = transform(PolynomialView::new(first.values()));
    let width = first.values.len();
    let remaining = rest.iter().map(|input| transform(PolynomialView::new(input.values())));
    spill_iter_to_disk(
        spill_dir,
        std::iter::once(first).chain(remaining),
        inputs.len(),
        width,
    )
}

#[cfg(test)]
mod test {
    use midnight_curves::Fq as Fp;

    use super::*;
    use crate::poly::LagrangeCoeff;

    fn poly(vals: &[u64]) -> Polynomial<Fp, LagrangeCoeff> {
        Polynomial {
            values: vals.iter().map(|v| Fp::from(*v)).collect(),
            _marker: std::marker::PhantomData,
        }
    }

    #[test]
    fn spill_round_trips_values() {
        let src = vec![poly(&[1, 2, 3, 4]), poly(&[5, 6, 7, 8])];
        let expected: Vec<Vec<Fp>> = src.iter().map(|p| p.values.clone()).collect();

        let spilled = spill_iter_to_disk(None, src, 2, 4).unwrap();
        let got = spilled.views();

        assert_eq!(got.len(), 2);
        for (i, p) in got.iter().enumerate() {
            assert_eq!(p.len(), 4, "poly {i} length");
            assert_eq!(
                &p[..],
                &expected[i],
                "poly {i} values survived the round trip"
            );
        }
    }

    #[test]
    fn spill_handles_the_empty_batch() {
        let spilled: MmappedPolys<Fp, LagrangeCoeff> =
            spill_iter_to_disk(None, Vec::new(), 0, 4).unwrap();
        assert!(spilled.views().is_empty());
        // Dropping an empty mapping must not fault either.
        drop(spilled);
    }

    #[test]
    fn dropping_does_not_free_mmap_pages() {
        // The descriptors own only Arcs, offsets, and lengths, so dropping them
        // must never send a mapped pointer to the global allocator.
        for _ in 0..8 {
            let spilled = spill_iter_to_disk(None, vec![poly(&[9, 9, 9, 9])], 1, 4).unwrap();
            assert_eq!(spilled.views()[0][0], Fp::from(9u64));
            drop(spilled);
        }
    }

    #[test]
    fn values_stay_readable_after_the_source_is_gone() {
        // The source polynomials are consumed and dropped during the spill; the
        // mapping must not alias their freed heap.
        let spilled = {
            let src = vec![poly(&[11, 22, 33, 44])];
            spill_iter_to_disk(None, src, 1, 4).unwrap()
        };
        assert_eq!(
            &spilled.views()[0][..],
            vec![
                Fp::from(11u64),
                Fp::from(22u64),
                Fp::from(33u64),
                Fp::from(44u64)
            ]
        );
    }

    #[test]
    fn rejects_a_mismatched_polynomial_length() {
        let error = spill_iter_to_disk(None, vec![poly(&[1, 2, 3])], 1, 4).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_a_wrong_declared_count_before_exposing_uninitialised_memory() {
        let too_many = vec![poly(&[1]), poly(&[2])];
        assert_eq!(
            spill_iter_to_disk(None, too_many, 1, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let too_few = vec![poly(&[1])];
        assert_eq!(
            spill_iter_to_disk(None, too_few, 2, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            spill_iter_to_disk(None, vec![poly(&[1])], 0, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

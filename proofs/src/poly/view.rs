//! Read-only polynomial access shared by owned and mapped storage.

use std::{fmt, marker::PhantomData, ops::Deref};

use super::Polynomial;

/// Minimal interface required by proving paths that only read polynomial
/// values. Implementations may own their values or expose a checked view over
/// another backing store.
pub(crate) trait PolynomialRead<F> {
    /// Representation/basis carried through every borrowed view.
    type Basis;

    fn values(&self) -> &[F];
}

impl<F, B> PolynomialRead<F> for Polynomial<F, B> {
    type Basis = B;

    fn values(&self) -> &[F] {
        &self.values
    }
}

/// A copyable, basis-typed read-only polynomial reference. Hot loops consume
/// this concrete type, so choosing owned versus mapped storage happens once at
/// the boundary and adds no virtual dispatch per field operation.
#[derive(Clone, Copy)]
pub(crate) struct PolynomialView<'a, F, B> {
    values: &'a [F],
    _marker: PhantomData<B>,
}

impl<'a, F, B> PolynomialView<'a, F, B> {
    pub(crate) fn new(values: &'a [F]) -> Self {
        Self {
            values,
            _marker: PhantomData,
        }
    }

    /// Materialise one owned polynomial. Spill callers use this only for the
    /// single polynomial currently being transformed, preserving the bounded
    /// peak-memory property.
    pub(crate) fn materialise(self) -> Polynomial<F, B>
    where
        F: Clone,
    {
        Polynomial {
            values: self.values.to_vec(),
            _marker: PhantomData,
        }
    }
}

impl<F, B> Deref for PolynomialView<'_, F, B> {
    type Target = [F];

    fn deref(&self) -> &[F] {
        self.values
    }
}

impl<F: fmt::Debug, B> fmt::Debug for PolynomialView<'_, F, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.values.fmt(f)
    }
}

impl<F, B> PolynomialRead<F> for PolynomialView<'_, F, B> {
    type Basis = B;

    fn values(&self) -> &[F] {
        self.values
    }
}

/// Adapt any homogeneous batch to the one concrete representation used by
/// read-only proving code. The allocation contains only slice fat-pointers;
/// coefficient storage is never copied.
pub(crate) fn polynomial_views<F, P>(polys: &[P]) -> Vec<PolynomialView<'_, F, P::Basis>>
where
    P: PolynomialRead<F>,
{
    polys.iter().map(|poly| PolynomialView::new(poly.values())).collect()
}

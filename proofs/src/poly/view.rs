//! Read-only polynomial access shared by owned and mapped storage.

use super::Polynomial;

/// Values required by the common polynomial serializer. Mapped storage can
/// implement this without constructing an owned `Polynomial` first.
pub(crate) trait PolynomialRead<F> {
    type Basis;

    fn values(&self) -> &[F];
}

impl<F, B> PolynomialRead<F> for Polynomial<F, B> {
    type Basis = B;

    fn values(&self) -> &[F] {
        &self.values
    }
}

impl<F, P: PolynomialRead<F> + ?Sized> PolynomialRead<F> for &P {
    type Basis = P::Basis;

    fn values(&self) -> &[F] {
        (*self).values()
    }
}

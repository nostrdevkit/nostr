pub(crate) use std::sync::MutexGuard as NonPoisoningMutexGuard;
use std::sync::{Mutex, PoisonError};

/// Adapter for `std::Mutex` that removes the poisoning aspects
/// from its API.
#[derive(Debug)]
pub(crate) struct NonPoisoningMutex<T>(Mutex<T>)
where
    T: ?Sized;

impl<T> NonPoisoningMutex<T> {
    #[inline]
    pub(crate) fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }

    #[inline]
    pub(crate) fn lock(&self) -> NonPoisoningMutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

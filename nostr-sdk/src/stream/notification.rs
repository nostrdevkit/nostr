use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Stream, StreamExt};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// A stream of notifications.
///
/// By default, notifications lost when this receiver falls behind are skipped.
pub struct NotificationStream<T> {
    inner: Option<BroadcastStream<T>>,
    is_terminal: fn(&T) -> bool,
}

impl<T> NotificationStream<T>
where
    T: Clone + Send + 'static,
{
    #[inline]
    pub(crate) fn new(inner: broadcast::Receiver<T>, is_terminal: fn(&T) -> bool) -> Self {
        Self {
            inner: Some(BroadcastStream::new(inner)),
            is_terminal,
        }
    }

    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            inner: None,
            is_terminal: |_| false,
        }
    }

    fn poll_next_with_err(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<T, BroadcastStreamRecvError>>> {
        let Some(inner) = &mut self.inner else {
            return Poll::Ready(None);
        };

        match inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(notification))) => {
                if (self.is_terminal)(&notification) {
                    self.inner = None;
                }
                Poll::Ready(Some(Ok(notification)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                self.inner = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Stream for NotificationStream<T>
where
    T: Clone + Send + Unpin + 'static,
{
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        loop {
            match stream.poll_next_with_err(cx) {
                Poll::Ready(Some(Ok(notification))) => return Poll::Ready(Some(notification)),
                Poll::Ready(Some(Err(..))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

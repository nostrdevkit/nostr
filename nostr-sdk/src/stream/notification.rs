use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Stream, StreamExt};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// Notifications skipped by one notification stream receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotificationGap {
    /// Number of notifications skipped by this receiver.
    pub skipped: u64,
}

/// A stream of notifications.
///
/// By default, notifications lost when this receiver falls behind are skipped.
/// Use [`NotificationStream::with_gaps`] to observe such losses.
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

    /// Report notification loss to this receiver.
    ///
    /// An error reports the number of notifications skipped by this receiver.
    /// The stream continues after the error. If no loss occurs, every item is `Ok`.
    #[inline]
    pub fn with_gaps(self) -> NotificationStreamWithGaps<T> {
        NotificationStreamWithGaps(self)
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

/// A notification stream that reports losses to its receiver.
///
/// A gap is emitted as an error, after which the stream continues.
pub struct NotificationStreamWithGaps<T>(NotificationStream<T>);

impl<T> Stream for NotificationStreamWithGaps<T>
where
    T: Clone + Send + Unpin + 'static,
{
    type Item = Result<T, NotificationGap>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream: &mut Self = self.get_mut();
        match stream.0.poll_next_with_err(cx) {
            Poll::Ready(Some(Ok(notification))) => Poll::Ready(Some(Ok(notification))),
            Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(skipped)))) => {
                Poll::Ready(Some(Err(NotificationGap { skipped })))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::sync::broadcast;

    use super::{NotificationGap, NotificationStream};

    #[tokio::test]
    async fn reports_repeated_gaps_and_continues() {
        let (sender, receiver) = broadcast::channel(2);

        let mut stream = NotificationStream::new(receiver, |value| *value == 99).with_gaps();

        for value in 0..8 {
            sender.send(value).unwrap();
        }

        assert_eq!(
            stream.next().await,
            Some(Err(NotificationGap { skipped: 6 }))
        );
        assert_eq!(stream.next().await, Some(Ok(6)));
        assert_eq!(stream.next().await, Some(Ok(7)));

        for value in 8..12 {
            sender.send(value).unwrap();
        }

        assert_eq!(
            stream.next().await,
            Some(Err(NotificationGap { skipped: 2 }))
        );
        assert_eq!(stream.next().await, Some(Ok(10)));
        assert_eq!(stream.next().await, Some(Ok(11)));

        sender.send(99).unwrap();

        assert_eq!(stream.next().await, Some(Ok(99)));
        assert_eq!(stream.next().await, None);
    }

    #[tokio::test]
    async fn gap_is_local_to_the_slow_receiver() {
        let (sender, receiver) = broadcast::channel(2);

        let mut fast = NotificationStream::new(receiver, |_| false).with_gaps();
        let mut slow = NotificationStream::new(sender.subscribe(), |_| false).with_gaps();

        for value in 0..8 {
            sender.send(value).unwrap();
            assert_eq!(fast.next().await, Some(Ok(value)));
        }

        assert_eq!(slow.next().await, Some(Err(NotificationGap { skipped: 6 })));
        assert_eq!(slow.next().await, Some(Ok(6)));
        assert_eq!(slow.next().await, Some(Ok(7)));
    }

    #[tokio::test]
    async fn ordinary_stream_skips_gaps_and_stops_after_terminal_notification() {
        let (sender, receiver) = broadcast::channel(2);

        let mut stream = NotificationStream::new(receiver, |value| *value == 99);

        for value in 0..8 {
            sender.send(value).unwrap();
        }

        assert_eq!(stream.next().await, Some(6));
        assert_eq!(stream.next().await, Some(7));

        sender.send(99).unwrap();

        assert_eq!(stream.next().await, Some(99));
        assert_eq!(stream.next().await, None);
    }

    #[tokio::test]
    async fn switching_to_gap_reporting_keeps_the_existing_receiver() {
        let (sender, receiver) = broadcast::channel(2);

        let stream = NotificationStream::new(receiver, |_| false);

        for value in 0..4 {
            sender.send(value).unwrap();
        }

        let mut stream = stream.with_gaps();

        assert_eq!(
            stream.next().await,
            Some(Err(NotificationGap { skipped: 2 }))
        );
        assert_eq!(stream.next().await, Some(Ok(2)));
        assert_eq!(stream.next().await, Some(Ok(3)));
    }
}

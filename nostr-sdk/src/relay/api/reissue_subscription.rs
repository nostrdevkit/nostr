use std::future::IntoFuture;

use nostr::message::SubscriptionId;

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::Relay;

/// Reissue a long-lived subscription
#[must_use = "Does nothing unless you await!"]
pub struct ReissueSubscription<'relay, 'id> {
    relay: &'relay Relay,
    id: &'id SubscriptionId,
}

impl<'relay, 'id> ReissueSubscription<'relay, 'id> {
    #[inline]
    pub(crate) fn new(relay: &'relay Relay, id: &'id SubscriptionId) -> Self {
        Self { relay, id }
    }
}

impl<'relay, 'id> IntoFuture for ReissueSubscription<'relay, 'id>
where
    'id: 'relay,
{
    type Output = Result<(), Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.relay.inner.reissue_subscription(self.id).await })
    }
}

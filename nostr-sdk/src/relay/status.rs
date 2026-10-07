use core::fmt;

/// Relay connection status
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayStatus {
    /// The relay has just been created.
    Initialized = 0,
    /// A connection has been requested or is being established.
    Connecting = 2,
    /// Connected.
    Connected = 3,
    /// The connection failed, but another attempt will occur soon.
    Disconnected = 4,
    /// No connection or automatic retry is scheduled. Call `connect` to reconnect.
    Idle = 5,
    /// The relay has been banned.
    Banned = 6,
    /// The relay is sleeping and will reconnect when activity resumes.
    Sleeping = 7,
    /// The relay has been shut down and can't be used again.
    Shutdown = 8,
}

impl fmt::Display for RelayStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialized => f.write_str("Initialized"),
            Self::Connecting => f.write_str("Connecting"),
            Self::Connected => f.write_str("Connected"),
            Self::Disconnected => f.write_str("Disconnected"),
            Self::Idle => f.write_str("Idle"),
            Self::Banned => f.write_str("Banned"),
            Self::Sleeping => f.write_str("Sleeping"),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

impl RelayStatus {
    #[inline]
    pub(crate) fn is_initialized(&self) -> bool {
        matches!(self, Self::Initialized)
    }

    /// Check if is [`RelayStatus::Connected`]
    #[inline]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Check if is [`RelayStatus::Disconnected`]
    pub(crate) fn is_disconnected(&self) -> bool {
        matches!(self, Self::Disconnected)
    }

    /// Check if is [`RelayStatus::Idle`]
    pub(crate) fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    /// Check if is [`RelayStatus::Banned`]
    pub(crate) fn is_banned(&self) -> bool {
        matches!(self, Self::Banned)
    }

    /// Check if is [`RelayStatus::Sleeping`]
    pub(crate) fn is_sleeping(&self) -> bool {
        matches!(self, Self::Sleeping)
    }

    /// Check if is [`RelayStatus::Shutdown`]
    pub(crate) fn is_shutdown(&self) -> bool {
        matches!(self, Self::Shutdown)
    }

    /// Check if relay can start a connection (initialized, idle or sleeping).
    #[inline]
    pub(crate) fn can_connect(&self) -> bool {
        matches!(self, Self::Initialized | Self::Idle | Self::Sleeping)
    }

    /// Check if is `disconnected`, `idle`, `banned`, `sleeping` or `shutdown`.
    #[inline]
    pub(crate) fn is_connection_closed(&self) -> bool {
        matches!(
            self,
            Self::Disconnected | Self::Idle | Self::Banned | Self::Sleeping | Self::Shutdown
        )
    }

    /// Check whether the relay is in a terminal state and cannot reconnect.
    #[inline]
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self, Self::Banned | Self::Shutdown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_initialized() {
        let status: RelayStatus = RelayStatus::Initialized;
        assert!(status.is_initialized());
        assert!(!status.is_connected());
        assert!(!status.is_disconnected());
        assert!(!status.is_idle());
        assert!(!status.is_banned());
        assert!(!status.is_sleeping());
        assert!(!status.is_shutdown());
        assert!(status.can_connect());
        assert!(!status.is_connection_closed());
        assert!(!status.is_terminal());
    }

    #[test]
    fn test_status_connecting() {
        let status: RelayStatus = RelayStatus::Connecting;
        assert!(!status.is_initialized());
        assert!(!status.is_connected());
        assert!(!status.is_disconnected());
        assert!(!status.is_idle());
        assert!(!status.is_banned());
        assert!(!status.is_sleeping());
        assert!(!status.is_shutdown());
        assert!(!status.can_connect());
        assert!(!status.is_connection_closed());
        assert!(!status.is_terminal());
    }

    #[test]
    fn test_status_connected() {
        let status: RelayStatus = RelayStatus::Connected;
        assert!(!status.is_initialized());
        assert!(status.is_connected());
        assert!(!status.is_disconnected());
        assert!(!status.is_idle());
        assert!(!status.is_banned());
        assert!(!status.is_sleeping());
        assert!(!status.is_shutdown());
        assert!(!status.can_connect());
        assert!(!status.is_connection_closed());
        assert!(!status.is_terminal());
    }

    #[test]
    fn test_status_disconnected() {
        let status: RelayStatus = RelayStatus::Disconnected;
        assert!(!status.is_initialized());
        assert!(!status.is_connected());
        assert!(status.is_disconnected());
        assert!(!status.is_idle());
        assert!(!status.is_banned());
        assert!(!status.is_sleeping());
        assert!(!status.is_shutdown());
        assert!(!status.can_connect());
        assert!(status.is_connection_closed());
        assert!(!status.is_terminal());
    }

    #[test]
    fn test_status_idle() {
        let status: RelayStatus = RelayStatus::Idle;
        assert!(!status.is_initialized());
        assert!(!status.is_connected());
        assert!(!status.is_disconnected());
        assert!(status.is_idle());
        assert!(!status.is_banned());
        assert!(!status.is_sleeping());
        assert!(!status.is_shutdown());
        assert!(status.can_connect());
        assert!(status.is_connection_closed());
        assert!(!status.is_terminal());
    }

    #[test]
    fn test_status_banned() {
        let status: RelayStatus = RelayStatus::Banned;
        assert!(!status.is_initialized());
        assert!(!status.is_connected());
        assert!(!status.is_disconnected());
        assert!(!status.is_idle());
        assert!(status.is_banned());
        assert!(!status.is_sleeping());
        assert!(!status.is_shutdown());
        assert!(!status.can_connect());
        assert!(status.is_connection_closed());
        assert!(status.is_terminal());
    }

    #[test]
    fn test_status_sleeping() {
        let status: RelayStatus = RelayStatus::Sleeping;
        assert!(!status.is_initialized());
        assert!(!status.is_connected());
        assert!(!status.is_disconnected());
        assert!(!status.is_idle());
        assert!(!status.is_banned());
        assert!(status.is_sleeping());
        assert!(!status.is_shutdown());
        assert!(status.can_connect());
        assert!(status.is_connection_closed());
        assert!(!status.is_terminal());
    }

    #[test]
    fn test_status_shutdown() {
        let status: RelayStatus = RelayStatus::Shutdown;
        assert!(!status.is_initialized());
        assert!(!status.is_connected());
        assert!(!status.is_disconnected());
        assert!(!status.is_idle());
        assert!(!status.is_banned());
        assert!(!status.is_sleeping());
        assert!(status.is_shutdown());
        assert!(!status.can_connect());
        assert!(status.is_connection_closed());
        assert!(status.is_terminal());
    }
}

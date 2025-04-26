use crate::utils::{
    get_client_device::ClientDevice,
    get_client_location::ClientLocation,
};
use serde::{
    Deserialize,
    Serialize,
};

/// The struct for storing a user's temporary blog login data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlogLoginTokenData {
    /// The user ID.
    pub uid: i64,
    /// The blog ID.
    pub bid: i64,
    /// Whether the session is persistent.
    pub persistent: bool,
    /// The user's [ClientLocation] value.
    pub loc: Option<ClientLocation>,
    /// The user's [ClientDevice] value.
    pub device: Option<ClientDevice>,
}

//! Storage backend for session state.

mod interface;
mod redis_rs;
mod session_key;
mod utils;

pub use self::{
    interface::{
        LoadError,
        SaveError,
        SessionStore,
        UpdateError,
    },
    session_key::{
        SessionKey,
        SessionKeySource,
    },
    utils::generate_session_key,
};
pub use redis_rs::{
    RedisSessionStore,
    RedisSessionStoreBuilder,
};

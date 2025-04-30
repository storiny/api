pub mod favicon;
pub mod init;
pub mod oauth;
pub mod robots;

#[cfg(test)]
pub use init::{
    GetLoginDetailsResponse,
    get_login_details,
};

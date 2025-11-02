pub mod proto;
pub mod relay;
pub mod auth;
pub mod handler;
pub mod net;
pub mod config;
pub mod telemetry;
pub mod server;

#[macro_export]
macro_rules! hex {
    ($val:expr) => {
        format_args!("{:x}", $val)
    };
}

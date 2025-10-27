pub mod proto;

#[macro_export]
macro_rules! hex {
    ($val:expr) => {
        format_args!("{:x}", $val)
    };
}

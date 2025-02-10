use std::time::{SystemTime, UNIX_EPOCH};
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod gossipper;
pub mod types;

pub fn get_current_time() -> u32 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as u32
}

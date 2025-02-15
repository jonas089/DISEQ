use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use colored::Colorize;
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

pub fn initial_print() {
    use viuer::{print_from_file, Config};
    clear_terminal();
    let config = Config {
        width: Some(50), // Set width in characters
        height: None,    // Auto-scale height
        ..Default::default()
    };
    let path = "./resources/DISEQ/icon-bg.jpg"; // Path to your image
    print_from_file(path, &config).expect("Failed to display image");
    println!(
        "{}",
        "Compact, General Purpose, Distrubed, Message Sequencer"
            .bold()
            .italic()
            .blue()
    );
}

fn clear_terminal() {
    print!("\x1b[2J\x1b[H");
    std::io::stdout().flush().unwrap();
}

use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use colored::Colorize;
pub mod api;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod gossipper;
pub mod node;
pub mod runtime;
pub mod state;
pub mod types;

pub fn get_current_time() -> u32 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as u32
}

pub fn get_current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

pub fn initial_print() {
    use viuer::{print_from_file, Config};
    clear_terminal();
    let config = Config {
        width: Some(60),
        height: None,
        ..Default::default()
    };
    let path = "./resources/DISEQ/icon-bg.jpg";
    // the logo is cosmetic, never fail startup over it
    let _ = print_from_file(path, &config);
    println!(
        "\n {} \n",
        "| WELCOME TO DISEQ - your open source, general purpose, message sequencer |"
            .bold()
            .italic()
            .blue()
    );
}

fn clear_terminal() {
    print!("\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
}

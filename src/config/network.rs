use lazy_static::lazy_static;
lazy_static! {
    pub static ref PEERS: Vec<&'static str> = vec![
        "rust-node-1:8080",
        "rust-node-2:8081",
        "rust-node-3:8082",
        "rust-node-4:8083"
    ];
}

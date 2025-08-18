use std::env;
use std::fs;
use std::path::Path;
use toml::Table;

fn main() {
    println!("cargo:rerun-if-changed=config.toml");
    println!("cargo:rerun-if-changed=ca-cert.pem");

    // Read and parse config.toml
    let config_str = match fs::read_to_string("config.toml") {
        Ok(content) => content,
        Err(e) => panic!("Failed to read config.toml: {}", e),
    };

    let config: Table = match config_str.parse() {
        Ok(parsed) => parsed,
        Err(e) => panic!("Failed to parse config.toml: {}", e),
    };

    // Extract values from config with better error messages
    let server_address = config.get("server_address")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("server_address not found or not a string in config.toml"));

    let server_sni = config.get("server_sni")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("server_sni not found or not a string in config.toml"));

    let ca_cert_path = config.get("ca_cert")  // Changed from ca_cert_path to ca_cert
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("ca_cert not found or not a string in config.toml"));

    // Read CA certificate
    let ca_cert = match fs::read_to_string(ca_cert_path) {
        Ok(content) => content,
        Err(e) => panic!("Failed to read CA certificate from {}: {}", ca_cert_path, e),
    };

    // Generate output
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("config.rs");

    let config_content = format!("\
pub const SERVER_ADDRESS: &str = \"{}\";
pub const SERVER_SNI: &str = \"{}\";
pub const CA_CERT: &str = r#\"{}\"#;
pub const CONFIG_TOML: &str = r#\"{}\"#;",
        server_address, server_sni, ca_cert, config_str
    );

    fs::write(&dest_path, config_content)
        .expect("Failed to write config.rs");
}
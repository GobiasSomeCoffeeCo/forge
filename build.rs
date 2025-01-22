use std::fs;
use std::env;
use std::path::Path;
use toml::Value;

fn main() {
    println!("cargo:rerun-if-changed=config.toml");
    println!("cargo:rerun-if-changed=ca.cert");

    // Read config.toml
    let config_str = fs::read_to_string("config.toml")
        .expect("Failed to read config.toml");
    
    let config: Value = toml::from_str(&config_str)
        .expect("Failed to parse config.toml");

    // Extract values
    let server_address = config["server_address"].as_str()
        .expect("server_address not found in config");
    let server_sni = config["server_sni"].as_str()
        .unwrap_or_else(|| server_address.split(':').next().unwrap());
    let ca_cert_path = config["ca_cert"].as_str()
        .expect("ca_cert not found in config");

    // Read CA certificate
    let ca_cert = fs::read_to_string(ca_cert_path)
        .expect("Failed to read CA certificate");

    // Generate output
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("config.rs");

    let config_content = format!(
        "pub const SERVER_ADDRESS: &str = \"{}\";\n\
         pub const SERVER_SNI: &str = \"{}\";\n\
         pub const CA_CERT: &str = \"{}\";\n",
        server_address,
        server_sni,
        ca_cert.replace("\"", "\\\"")  // Escape any quotes in the cert
    );

    // Write the file
    fs::write(&dest_path, config_content)
        .expect("Failed to write config.rs");
}
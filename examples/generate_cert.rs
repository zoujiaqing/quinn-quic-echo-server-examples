use {
    anyhow::{Context, Result},
    clap::Parser,
    quinn_echo_server::configure,
    std::path::PathBuf,
};

#[derive(Parser)]
#[clap(name = "Certificate Generator")]
struct Cli {
    /// Path to save the certificate
    #[clap(long, default_value = "public.pem")]
    cert: PathBuf,

    /// Path to save the private key
    #[clap(long, default_value = "private.pem")]
    key: PathBuf,
}

fn main() -> Result<()> {
    // 解析命令行参数
    let args = Cli::parse();
    
    println!("Generating self-signed certificate...");
    println!("Certificate will be saved to: {}", args.cert.display());
    println!("Private key will be saved to: {}", args.key.display());
    
    // 生成证书和私钥
    let subject_alt_names = vec!["localhost".to_string()];
    let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;
    
    // 将证书保存为PEM文件
    std::fs::write(&args.cert, cert.pem()).context("Failed to write certificate file")?;
    println!("Certificate saved successfully");
    
    // 将私钥保存为PEM文件
    std::fs::write(&args.key, key_pair.serialize_pem()).context("Failed to write private key file")?;
    println!("Private key saved successfully");
    
    println!("\nYou can now use these files with the server and client:");
    println!("  Server: cargo run --example server -- --usepem --cert-pem {} --key-pem {}", 
             args.cert.display(), args.key.display());
    println!("  Client: cargo run --example client -- --cert-pem {}", args.cert.display());
    
    Ok(())
} 
use anyhow::Result;
use clap::{Parser, Subcommand};
use susi_core::fingerprint;
use susi_core::usb;

#[derive(Parser)]
#[command(name = "susi-helper", about = "SUSI helper utilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the hardware fingerprint of this machine
    Fingerprint,
    /// List serial numbers of all connected USB drives
    ListUsbSerials,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Fingerprint => {
            let code = fingerprint::get_machine_code()?;
            println!("Fingerprint of this machine:");
            println!("{}", code);
        }
        Commands::ListUsbSerials => {
            let devices = usb::enumerate_usb_devices()?;
            if devices.is_empty() {
                println!("No USB mass storage devices found.");
            } else {
                let name_w = devices.iter().map(|d| d.name.len()).max().unwrap_or(4).max(4);
                let serial_w = devices.iter().map(|d| d.serial.len()).max().unwrap_or(6).max(6);
                println!("{:<name_w$}  {:<serial_w$}", "NAME", "SERIAL");
                println!("{:-<name_w$}  {:-<serial_w$}", "", "");
                for dev in &devices {
                    println!("{:<name_w$}  {:<serial_w$}", dev.name, dev.serial);
                }
            }
        }
    }
    Ok(())
}

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, BufRead, Write};
use susi_core::fingerprint;
use susi_core::usb;

#[derive(Parser)]
#[command(name = "susi-helper", about = "SUSI helper utilities")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the hardware fingerprint of this machine
    Fingerprint,
    /// List serial numbers of all connected USB drives
    ListUsbSerials,
}

fn print_fingerprint() -> Result<()> {
    let code = fingerprint::get_machine_code()?;
    println!("Fingerprint of this machine:");
    println!("{}", code);
    Ok(())
}

fn print_usb_serials() -> Result<()> {
    let devices = usb::enumerate_usb_devices()?;
    if devices.is_empty() {
        println!("No USB mass storage devices found.");
        return Ok(());
    }
    let name_w = devices.iter().map(|d| d.name.len()).max().unwrap_or(4).max(4);
    let serial_w = devices.iter().map(|d| d.serial.len()).max().unwrap_or(6).max(6);
    println!("{:<name_w$}  {:<serial_w$}", "NAME", "SERIAL");
    println!("{:-<name_w$}  {:-<serial_w$}", "", "");
    for dev in &devices {
        println!("{:<name_w$}  {:<serial_w$}", dev.name, dev.serial);
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Some(Commands::Fingerprint) => print_fingerprint(),
        Some(Commands::ListUsbSerials) => print_usb_serials(),
        None => {
            if let Err(e) = print_fingerprint() {
                println!("Failed to read fingerprint: {e:#}");
            }
            println!();
            println!("USB drives:");
            if let Err(e) = print_usb_serials() {
                println!("Failed to list USB drives: {e:#}");
            }
            println!();
            print!("Press Enter to close...");
            io::stdout().flush()?;
            io::stdin().lock().read_line(&mut String::new())?;
            Ok(())
        }
    }
}

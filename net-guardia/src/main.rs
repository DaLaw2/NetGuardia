use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use net_guardia_common::model::flow_status::FlowStatus;
use net_guardia_common::model::general::AddrPortV4;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use log::info;
use tokio::signal;
use tokio::time;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "5")]
    interval: u64,
}

async fn print_stats(ebpf: &mut aya::Ebpf, map_name: &str) -> anyhow::Result<()> {
    let status_map: HashMap<_, AddrPortV4, FlowStatus> =
        HashMap::try_from(ebpf.map_mut(map_name).unwrap())?;

    println!("\n{} Statistics:", map_name);
    println!(
        "{:<15} {:<8} {:<10} {:<10} {:<15}",
        "IP", "Port", "Packets", "Bytes", "Last Seen"
    );
    println!("{}", "-".repeat(60));

    for result in status_map.iter() {
        let (key, status) = result?;
        let ip = Ipv4Addr::from(u32::from_be(key[0]));
        let last_seen = Duration::from_nanos(status[2]);
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));
        let seconds_ago = if epoch > last_seen {
            (epoch - last_seen).as_secs()
        } else {
            0
        };
        println!(
            "{:<15} {:<8} {:<10} {:<10} {:<15}s ago",
            ip, key[1], status[1], status[0], seconds_ago
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/net-guardia"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = ebpf.program_mut("net_guardia").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    info!("Successfully attached XDP program to {}", opt.iface);

    let mut interval = time::interval(Duration::from_secs(opt.interval));
    let ctrl_c = signal::ctrl_c();

    println!("Starting statistics monitoring (Ctrl-C to exit)...");
    println!("Monitoring interface: {}", opt.iface);
    println!("Update interval: {} seconds", opt.interval);

    tokio::select! {
        _ = async {
            loop {
                interval.tick().await;
                
                // Print statistics for each time window
                if let Err(e) = print_stats(&mut ebpf, "SRC_STATS_IPV4_1MIN").await {
                    warn!("Error printing 1-minute source statistics: {}", e);
                }
                if let Err(e) = print_stats(&mut ebpf, "DST_STATS_IPV4_1MIN").await {
                    warn!("Error printing 1-minute destination statistics: {}", e);
                }
                if let Err(e) = print_stats(&mut ebpf, "SRC_STATS_IPV4_10MIN").await {
                    warn!("Error printing 10-minute source statistics: {}", e);
                }
                if let Err(e) = print_stats(&mut ebpf, "DST_STATS_IPV4_10MIN").await {
                    warn!("Error printing 10-minute destination statistics: {}", e);
                }
                println!("\n{}", "=".repeat(80));
            }
        } => {}
        _ = ctrl_c => println!("\nReceived Ctrl-C, shutting down...")
    }

    Ok(())
}

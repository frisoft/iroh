use clap::{Parser, Subcommand};
use iroh::hp::{
    self,
    derp::{DerpMap, UseIpv4, UseIpv6},
};
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    Report {
        #[clap(long, default_value = "derp.iroh.computer")]
        host_name: String,
        #[clap(long, default_value_t = 3478)]
        stun_port: u16,
    },
}

#[derive(Parser, Debug, Clone)]
#[clap(version)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

async fn report(host_name: String, stun_port: u16) -> anyhow::Result<()> {
    let mut client = hp::netcheck::Client::new(None).await?;

    let derp_port = 0;
    let derp_ipv4 = UseIpv4::None;
    let derp_ipv6 = UseIpv6::None;
    let dm = DerpMap::default_from_node(host_name, stun_port, derp_port, derp_ipv4, derp_ipv6);
    println!("getting report using derp map {:#}", dm);

    let r = client.get_report(&dm, None, None).await?;
    println!("{:#}", r);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();

    let cli = Cli::parse();
    match cli.command {
        Commands::Report {
            host_name,
            stun_port,
        } => report(host_name, stun_port).await,
    }
}

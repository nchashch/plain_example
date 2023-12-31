use anyhow::Result;
use clap::Parser;
use custom::{Authorization, CustomContent, CustomState};
use plain_api::node::node_server::NodeServer;
use std::{net::SocketAddr, path::PathBuf};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    const DEFAULT_RPC_PORT: u16 = 3000;
    const DEFAULT_NET_PORT: u16 = 4000;
    let args = Cli::parse();
    let rpc_port = args.rpcport.unwrap_or(DEFAULT_RPC_PORT);
    let net_port = args.netport.unwrap_or(DEFAULT_NET_PORT);
    let rpc_addr = format!("[::1]:{rpc_port}").parse()?;
    let net_addr: SocketAddr = format!("127.0.0.1:{net_port}").parse()?;
    let datadir = args
        .datadir
        .unwrap_or(project_root::get_project_root()?.join("target/plain"));
    let mut node = ddk::node::Node::<Authorization, CustomContent, CustomState>::new(
        &datadir,
        net_addr,
        "localhost",
        18443,
    )?;
    node.run()?;
    println!("RPC server is running on {rpc_addr}");

    Server::builder()
        .add_service(NodeServer::new(node))
        .serve(rpc_addr)
        .await?;

    Ok(())
}

#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct Cli {
    /// P2P networking port.
    #[arg(short, long)]
    pub netport: Option<u16>,
    /// RPC port.
    #[arg(short, long)]
    pub rpcport: Option<u16>,
    /// Directory for storing block data, headers, config file.
    #[arg(short, long)]
    pub datadir: Option<PathBuf>,
}

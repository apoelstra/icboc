
use anyhow::{self, Context};
use jsonrpc;
use shellexpand;
use std::fs;
use std::time::Duration;

use crate::commands::Options;

pub struct Bitcoind {
    rpc_client: jsonrpc::Client,
}

impl Bitcoind {
    /// Connect to a bitcoind over JSONRPC
    pub fn connect(opts: &Options) -> anyhow::Result<Bitcoind> {
        let cookie_file = shellexpand::full(&opts.rpccookie)?;
        let userpass = fs::read_to_string(&*cookie_file)
            .with_context(|| format!("opening file {}", cookie_file))?;
        let transport = jsonrpc::simple_http::Builder::new()
            .timeout(Duration::from_millis(100))
            .cookie_auth(&userpass)
            .build();
        Ok(Bitcoind {
            rpc_client: jsonrpc::Client::with_transport(transport),
        })
    }

    /// Get the number of blocks the bitcoind is aware of
    pub fn getblockcount(&self) -> anyhow::Result<usize> {
        Ok(self.rpc_client.call("getblockcount", &[])?)
    }
}


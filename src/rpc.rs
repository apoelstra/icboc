use anyhow::{self, Context};
use jsonrpc::{self, arg};
use miniscript::bitcoin;
use miniscript::bitcoin::hashes::{hex, sha256d};
use std::borrow::Cow;
use std::fs;
use std::path::Path;
use std::time::Duration;

pub struct Bitcoind {
    rpc_client: jsonrpc::Client,
}

impl Bitcoind {
    /// Connect to a bitcoind over JSONRPC
    pub fn connect(rpccookie: &str, timeout_ms: u64) -> anyhow::Result<Bitcoind> {
        let cookie_file = if &rpccookie.as_bytes()[0..2] == b"~/" {
            Cow::Owned(
                home::home_dir()
                    .expect("finding home directory")
                    .join(&rpccookie[2..]),
            )
        } else {
            Cow::Borrowed(Path::new(&rpccookie))
        };
        let userpass = fs::read_to_string(&*cookie_file)
            .with_context(|| format!("opening file {}", cookie_file.to_string_lossy()))?;
        let transport = jsonrpc::simple_http::Builder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .cookie_auth(&userpass)
            .build();
        Ok(Bitcoind {
            rpc_client: jsonrpc::Client::with_transport(transport),
        })
    }

    /// Get the number of blocks the bitcoind is aware of
    pub fn getblockcount(&self) -> anyhow::Result<u64> {
        Ok(self.rpc_client.call("getblockcount", &[])?)
    }

    /// Get a block at a specified height
    pub fn getblock(&self, index: u64) -> anyhow::Result<bitcoin::Block> {
        let hash: sha256d::Hash = self
            .rpc_client
            .call("getblockhash", &[arg(index)])
            .with_context(|| format!("getting hash of block {}", index))?;
        let hex: String = self
            .rpc_client
            .call("getblock", &[arg(hash), arg(0)])
            .with_context(|| format!("getting hex of block {} ({})", index, hash))?;
        let bytes: Vec<u8> = hex::FromHex::from_hex(&hex)
            .with_context(|| format!("deserializing hex of block {} ({})", index, hash))?;
        bitcoin::consensus::deserialize(&bytes)
            .with_context(|| format!("decoding block {} ({})", index, hash))
    }
}

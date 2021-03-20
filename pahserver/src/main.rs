#![allow(clippy::try_err)]

use crate::port::{ReadPort, WritePort};
use crate::util::SimpleResult;
use hex::FromHex;
use serde::{Deserialize, Deserializer};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use std::error::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use structopt::StructOpt;

mod port;
mod util;

#[derive(StructOpt)]
/// The permuter@home control server.
#[structopt(name = "pahserver")]
struct CmdOpts {
    /// Port to listen on (0-65535)
    #[structopt(long)]
    port: u16,

    /// Path to TOML configuration file
    #[structopt(long)]
    config: String,

    /// Path to SQLite database
    #[structopt(long)]
    db: String,
}

#[derive(Deserialize)]
struct Config {
    docker_image: String,
    #[serde(deserialize_with = "seed_from_hex")]
    priv_seed: sign::Seed,
}

struct State {
    docker_image: String,
    sign_sk: sign::SecretKey,
}

pub fn seed_from_hex<'de, D>(deserializer: D) -> Result<sign::Seed, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let string = String::deserialize(deserializer)?;
    let val = Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string()))?;
    sign::Seed::from_slice(&val).ok_or_else(|| Error::custom("Seed must be 32 bytes"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    sodiumoxide::init().map_err(|()| "Failed to initialize cryptography library")?;

    let opts = CmdOpts::from_args();

    let config: Config = toml::from_str(&fs::read_to_string(&opts.config).await?)?;
    let (_, sign_sk) = sign::keypair_from_seed(&config.priv_seed);
    let state: &'static State = Box::leak(Box::new(State {
        docker_image: config.docker_image,
        sign_sk,
    }));

    let listener = TcpListener::bind(("127.0.0.1", opts.port)).await?;

    loop {
        // The second item contains the IP and port of the new connection.
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, state).await {
                eprintln!("Broken server connection: error={:?}", e);
            }
        });
    }
}

async fn server_read(port: &mut ReadPort<'_>) -> SimpleResult<()> {
    port.read().await?;
    Ok(())
}

async fn server_write(port: &mut WritePort<'_>) -> SimpleResult<()> {
    port.write(&"hello".as_bytes()).await?;
    Ok(())
}

async fn handshake<'a>(
    mut rd: ReadHalf<'a>,
    mut wr: WriteHalf<'a>,
    sign_sk: &sign::SecretKey,
) -> SimpleResult<(ReadPort<'a>, WritePort<'a>, Box<[u8]>)> {
    let mut buffer = [0; 4 + 32];
    rd.read_exact(&mut buffer[..]).await?;
    let (magic, their_pk) = buffer.split_at(4);
    if magic != b"p@h0" {
        Err("Invalid protocol version")?;
    }
    let their_pk = box_::PublicKey::from_slice(&their_pk).unwrap();

    let (our_pk, our_sk) = box_::gen_keypair();
    let mut msg = Vec::with_capacity(6 + 32 + 32);
    msg.extend(b"HELLO:");
    msg.extend(their_pk.as_ref());
    msg.extend(our_pk.as_ref());
    let buffer = sign::sign(&msg[..], sign_sk);
    wr.write(&buffer[..]).await?;

    let key = box_::precompute(&their_pk, &our_sk);
    let mut read_port = ReadPort::new(rd, &key);
    let write_port = WritePort::new(wr, &key);

    let hello = read_port.read().await?;
    if hello.len() != 32 + 64 {
        Err("Failed to perform secret handshake")?;
    }
    let (client_ver_key, client_signature) = hello.split_at(32);
    let client_ver_key = sign::PublicKey::from_slice(client_ver_key).unwrap();
    let client_signature = sign::Signature::from_slice(client_signature).unwrap();
    let mut msg = Vec::with_capacity(6 + 32);
    msg.extend(b"WORLD:");
    msg.extend(our_pk.as_ref());
    if !sign::verify_detached(&client_signature, &msg[..], &client_ver_key) {
        Err("Spoofed client signature!")?;
    }

    Ok((read_port, write_port, client_signature.as_ref().into()))
}

async fn handle_connection(mut socket: TcpStream, state: &State) -> SimpleResult<()> {
    let (rd, wr) = socket.split();
    let (mut read_port, mut write_port, _client_id) = handshake(rd, wr, &state.sign_sk).await?;
    // TODO: look up client_id in DB

    let r = tokio::try_join!(server_read(&mut read_port), server_write(&mut write_port));
    // wr.shutdown().await?;
    r?;
    Ok(())
}

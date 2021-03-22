#![allow(clippy::try_err)]

use std::default::Default;

use hex::FromHex;
use serde::Deserialize;
use serde_json::json;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use structopt::StructOpt;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};

use crate::port::{ReadPort, WritePort};
use crate::save::{SaveType, SaveableDB};
use pahserver::db::{ByteString, User, UserId};
use pahserver::util::SimpleResult;

mod port;
mod save;

#[derive(StructOpt)]
/// The permuter@home control server.
#[structopt(name = "pahserver")]
struct CmdOpts {
    /// ip:port to listen on (e.g. 0.0.0.0:1234)
    #[structopt(long)]
    listen_on: String,

    /// Path to TOML configuration file
    #[structopt(long)]
    config: String,

    /// Path to JSON database
    #[structopt(long)]
    db: String,
}

#[derive(Deserialize)]
struct Config {
    docker_image: String,
    priv_seed: ByteString,
}

struct State {
    docker_image: String,
    sign_sk: sign::SecretKey,
    db: SaveableDB,
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
enum Request {
    Ping,
    Vouch { who: UserId, signed_name: String },
    ConnectServer,
    ConnectClient,
}

#[tokio::main]
async fn main() -> SimpleResult<()> {
    sodiumoxide::init().map_err(|()| "Failed to initialize cryptography library")?;

    let opts = CmdOpts::from_args();

    let config: Config = toml::from_str(&fs::read_to_string(&opts.config).await?)?;
    let (_, sign_sk) = sign::keypair_from_seed(&config.priv_seed.to_seed());

    let state: &'static State = Box::leak(Box::new(State {
        docker_image: config.docker_image,
        sign_sk,
        db: SaveableDB::open(&opts.db)?,
    }));

    let listener = TcpListener::bind(opts.listen_on).await?;

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
) -> SimpleResult<(ReadPort<'a>, WritePort<'a>, UserId)> {
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

    Ok((read_port, write_port, UserId::from_pubkey(&client_ver_key)))
}

async fn handle_connection(mut socket: TcpStream, state: &State) -> SimpleResult<()> {
    let (rd, wr) = socket.split();
    let (mut read_port, mut write_port, user_id) = handshake(rd, wr, &state.sign_sk).await?;
    if !state.db.read(|db| db.users.contains_key(&user_id)) {
        Err("Unknown client!")?;
    }

    let request = read_port.read().await?;
    let request: Request = serde_json::from_slice(&request)?;
    match request {
        Request::Ping => {
            write_port.write_json(&json!({})).await?;
        }
        Request::Vouch { who, signed_name } => {
            let signed_name = Vec::from_hex(&signed_name).map_err(|_| "not a valid hex string")?;
            let name = String::from_utf8(
                sign::verify(&signed_name, &who.to_pubkey()).map_err(|()| "bad name signature")?,
            )?;
            state.db.write(SaveType::Immediate, |db| {
                db.users.entry(who).or_insert_with(|| User {
                    trusted_by: Some(user_id),
                    name,
                    client_stats: Default::default(),
                    server_stats: Default::default(),
                });
            });
            write_port.write_json(&json!({})).await?;
        }
        Request::ConnectServer => {
            write_port
                .write_json(&json!({
                    "docker_image": &state.docker_image,
                }))
                .await?;
        }
        Request::ConnectClient => {
            write_port.write_json(&json!({})).await?;
        }
    };

    let r = tokio::try_join!(server_read(&mut read_port), server_write(&mut write_port));
    // wr.shutdown().await?;
    r?;
    Ok(())
}

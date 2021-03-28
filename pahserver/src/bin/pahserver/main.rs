#![allow(clippy::try_err)]

use std::collections::{HashMap, VecDeque};
use std::default::Default;
use std::sync::{Arc, Mutex};

use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use slotmap::{new_key_type, SlotMap};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use structopt::StructOpt;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::port::{ReadPort, WritePort};
use crate::save::SaveableDB;
use pahserver::db::{ByteString, User, UserId};
use pahserver::util::SimpleResult;

mod client;
mod port;
mod save;
mod server;

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
    priv_seed: ByteString<32>,
}

#[derive(Deserialize, Serialize)]
struct PermuterData {
    fn_name: String,
    filename: String,
    keep_prob: f64,
    stack_differences: bool,
    compile_script: String,
    #[serde(skip)]
    source: String,
    #[serde(skip)]
    target_o_bin: Vec<u8>,
}

#[derive(Deserialize)]
struct ConnectServerData {
    min_priority: f64,
    num_cpus: u32,
}

#[derive(Deserialize)]
struct ConnectClientData {
    priority: f64,
    permuters: Vec<PermuterData>,
}

#[derive(Deserialize, Clone, Copy)]
struct PermuterWork {
    seed: u128,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerUpdate {
    Result,
    InitDone,
    InitFailed,
}

enum PermuterResult {
    NeedWork,
    Result(UserId, ServerUpdate),
}

type PermuterId = u64;

struct Permuter {
    data: Arc<PermuterData>,
    work_queue: VecDeque<PermuterWork>,
    result_tx: mpsc::UnboundedSender<(PermuterId, PermuterResult)>,
    stale: bool,
    priority: f64,
    energy_add: f64,
}

new_key_type! { struct ServerId; }

struct ConnectedServer {
    min_priority: f64,
    num_cpus: u32,
}

struct MutableState {
    servers: SlotMap<ServerId, ConnectedServer>,
    permuters: HashMap<PermuterId, Permuter>,
    wake_on_more_work: Vec<oneshot::Sender<()>>,
    next_permuter_id: PermuterId,
}

impl MutableState {
    fn wake_sleepers(&mut self) {
        for tx in self.wake_on_more_work.drain(..) {
            let _ = tx.send(());
        }
    }
}

struct State {
    docker_image: String,
    sign_sk: sign::SecretKey,
    db: SaveableDB,
    m: Mutex<MutableState>,
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum Request {
    Ping,
    Vouch {
        who: UserId,
        signed_name: String,
    },
    ConnectServer {
        #[serde(flatten)]
        data: ConnectServerData,
    },
    ConnectClient {
        #[serde(flatten)]
        data: ConnectClientData,
    },
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
        m: Mutex::new(MutableState {
            servers: SlotMap::with_key(),
            permuters: HashMap::new(),
            wake_on_more_work: Vec::new(),
            next_permuter_id: 0,
        }),
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
            state
                .db
                .write(true, |db| {
                    db.users.entry(who).or_insert_with(|| User {
                        trusted_by: Some(user_id),
                        name,
                        client_stats: Default::default(),
                        server_stats: Default::default(),
                    });
                })
                .await;
            write_port.write_json(&json!({})).await?;
        }
        Request::ConnectServer { data } => {
            server::handle_connect_server(read_port, write_port, &user_id, state, data).await?;
        }
        Request::ConnectClient { data } => {
            client::handle_connect_client(read_port, write_port, &user_id, state, data).await?;
        }
    };

    Ok(())
}

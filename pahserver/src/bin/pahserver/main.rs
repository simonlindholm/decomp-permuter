#![allow(clippy::try_err)]
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::default::Default;
use std::sync::{Arc, Mutex};

use hex::FromHex;
use ordered_float::NotNan;
use serde::Deserialize;
use serde_json::json;
use slotmap::{SlotMap, SparseSecondaryMap, new_key_type};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use structopt::StructOpt;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::port::{ReadPort, WritePort};
use crate::save::SaveableDB;
use pahserver::db::{ByteString, User, UserId};
use pahserver::util::SimpleResult;

mod port;
mod save;

const SERVER_WORK_QUEUE_SIZE: usize = 100;
const SETUP_COST: f64 = 100.0;

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

#[derive(Deserialize)]
struct ConnectServerData {
    min_priority: f64,
    num_cpus: u32,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    NeedWork,
    Result,
}

#[derive(Deserialize)]
struct Permuter {
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
struct ConnectClientData {
    priority: f64,
    permuters: Vec<Permuter>,
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

struct ConnectedServer {
    min_priority: f64,
    num_cpus: u32,
}

#[derive(Clone, Copy)]
struct PermuterWork {
    seed: u128,
}

struct PermuterServerState;

new_key_type! { struct ServerId; }

struct ActivePermuter {
    permuter: Arc<Permuter>,
    server_state: SparseSecondaryMap<ServerId, PermuterServerState>,
    work_queue: VecDeque<PermuterWork>,
    stale: bool,
    energy: f64,
    energy_add: f64,
}

struct MutableState {
    servers: SlotMap<ServerId, ConnectedServer>,
    permuters: HashMap<u64, ActivePermuter>,
    wake_on_more_work: Vec<oneshot::Sender<()>>,
    next_permuter_id: u64,
}

struct State {
    docker_image: String,
    sign_sk: sign::SecretKey,
    db: SaveableDB,
    m: Mutex<MutableState>,
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

async fn server_read(port: &mut ReadPort<'_>, work_queue: &mpsc::Sender<()>) -> SimpleResult<()> {
    loop {
        let msg = port.read().await?;
        let msg: ServerMessage = serde_json::from_slice(&msg)?;
        match msg {
            ServerMessage::NeedWork => {}
            ServerMessage::Result => {
                // TODO: send result on to client
            }
        }

        // Try requesting more work by sending a message to the writer thread.
        // If the queue is full (because the writer thread is blocked on a
        // send), drop the request to avoid an unbounded backlog.
        if let Err(TrySendError::Closed(_)) = work_queue.try_send(()) {
            break;
        }
    }
    Ok(())
}

fn permuter_cost(id: ServerId, perm: &ActivePermuter) -> NotNan<f64> {
    let cost = if perm.server_state.contains_key(id) { SETUP_COST } else { 1.0 };
    let ret = perm.energy + perm.energy_add * cost;
    NotNan::new(ret).unwrap()
}

async fn server_write(
    port: &mut WritePort<'_>,
    id: ServerId,
    state: &State,
    mut work_queue: mpsc::Receiver<()>,
) -> SimpleResult<()> {
    loop {
        if matches!(work_queue.recv().await, None) {
            break;
        }

        enum ToSend {
            SendWork(PermuterWork),
            SendPermuter(Arc<Permuter>),
        }

        let mut wait_for: Option<oneshot::Receiver<()>> = None;
        let (perm_id, to_send) = loop {
            if let Some(rx) = wait_for {
                rx.await.unwrap();
            }
            let mut m = state.m.lock().unwrap();
            let (perm_id, perm) = match m.permuters
                    .iter_mut()
                    .filter(|(_, p)| !p.stale)
                    .min_by_key(|(_, p)| permuter_cost(id, &p)) {
                Some(kv) => kv,
                _ => {
                    // No permuters. Register to be notified when there's more
                    // work and go to sleep.
                    let (tx, rx) = oneshot::channel();
                    m.wake_on_more_work.push(tx);
                    wait_for = Some(rx);
                    continue;
                },
            };

            let perm_id = *perm_id;
            let to_send = if perm.server_state.contains_key(id) {
                match perm.work_queue.pop_front() {
                    None => {
                        // TODO: ask for more work
                        perm.stale = true;
                        wait_for = None;
                        continue;
                    }
                    Some(work) => {
                        perm.energy += perm.energy_add;
                        ToSend::SendWork(work)
                    }
                }
            } else {
                perm.energy += perm.energy_add * SETUP_COST;
                perm.server_state.insert(id, PermuterServerState {});
                ToSend::SendPermuter(perm.permuter.clone())
            };

            // Adjust energies to be around zero, to avoid problems with float
            // imprecision, and to ensure that new permuters that come in with
            // energy zero will fit the schedule.
            if let Some(perm) = m.permuters
                    .values()
                    .filter(|p| !p.stale)
                    .min_by_key(|p| NotNan::new(p.energy).unwrap()) {
                let min_energy = perm.energy;
                for perm in m.permuters.values_mut() {
                    perm.energy -= min_energy;
                }
            }

            break (perm_id, to_send);
        };

        match to_send {
            ToSend::SendWork(PermuterWork { seed }) => {
                port.write_json(&json!({
                    "type": "work",
                    "permuter": perm_id,
                    "seed": seed,
                })).await?;
            }
            ToSend::SendPermuter(_) => {}
        }

    }
    Ok(())
}

async fn handle_connect_server<'a>(
    mut read_port: ReadPort<'a>,
    mut write_port: WritePort<'a>,
    _who: &UserId,
    state: &State,
    data: ConnectServerData,
) -> SimpleResult<()> {
    write_port
        .write_json(&json!({
            "docker_image": &state.docker_image,
        }))
        .await?;

    let id = {
        let mut m = state.m.lock().unwrap();
        m.servers.insert(ConnectedServer {
            min_priority: data.min_priority,
            num_cpus: data.num_cpus,
        })
    };

    let (tx, rx) = mpsc::channel(SERVER_WORK_QUEUE_SIZE);
    let r = tokio::try_join!(
        server_read(&mut read_port, &tx),
        server_write(&mut write_port, id, state, rx)
    );

    state.m.lock().unwrap().servers.remove(id);
    r?;
    Ok(())
}

async fn handle_connect_client<'a>(
    mut read_port: ReadPort<'a>,
    mut write_port: WritePort<'a>,
    _who: &UserId,
    state: &State,
    mut data: ConnectClientData,
) -> SimpleResult<()> {
    for permuter in &mut data.permuters {
        permuter.source = String::from_utf8(read_port.read_compressed().await?)?;
        permuter.target_o_bin = read_port.read_compressed().await?;
    }
    write_port.write_json(&json!({})).await?;

    // TODO: validate that priority is sane
    let energy_add = (data.permuters.len() as f64) / data.priority;

    let mut perm_ids = Vec::new();
    {
        let mut m = state.m.lock().unwrap();
        for permuter in data.permuters {
            let id = m.next_permuter_id;
            m.next_permuter_id += 1;
            perm_ids.push(id);
            m.permuters.insert(id, ActivePermuter {
                permuter: permuter.into(),
                server_state: Default::default(),
                work_queue: VecDeque::new(),
                stale: false,
                energy: 0.0,
                energy_add,
            });
        }
    }

    // TODO: do work

    {
        let mut m = state.m.lock().unwrap();
        for id in perm_ids {
            m.permuters.remove(&id);
            // TODO: send signal to remove from servers
        }
    }

    Ok(())
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
            handle_connect_server(read_port, write_port, &user_id, state, data).await?;
        }
        Request::ConnectClient { data } => {
            handle_connect_client(read_port, write_port, &user_id, state, data).await?;
        }
    };

    Ok(())
}

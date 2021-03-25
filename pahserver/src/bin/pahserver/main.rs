#![allow(clippy::try_err)]
#![allow(dead_code)]

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
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot;

use crate::port::{ReadPort, WritePort};
use crate::save::SaveableDB;
use pahserver::db::{ByteString, User, UserId};
use pahserver::util::SimpleResult;

mod port;
mod save;

const SERVER_WORK_QUEUE_SIZE: usize = 100;

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
enum ServerUpdate {
    Result,
    InitDone,
    InitFailed,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    NeedWork,
    Update {
        permuter_id: u64,
        update: ServerUpdate,
    },
}

#[derive(Deserialize, Serialize)]
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

#[derive(Clone, Copy)]
struct PermuterWork {
    seed: u128,
}

enum JobState {
    Loading,
    Loaded,
    Failed,
}

struct Job {
    state: JobState,
    energy: f64,
}

struct ServerState {
    min_priority: f64,
    jobs: HashMap<u64, Job>,
}

struct ConnectedServer {
    min_priority: f64,
    num_cpus: u32,
}

new_key_type! { struct ServerId; }

struct ActivePermuter {
    permuter: Arc<Permuter>,
    work_queue: VecDeque<PermuterWork>,
    stale: bool,
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

async fn server_read(
    port: &mut ReadPort<'_>,
    server_state: &Mutex<ServerState>,
    _state: &State,
    more_work_tx: mpsc::Sender<()>,
) -> SimpleResult<()> {
    loop {
        let msg = port.read().await?;
        let msg: ServerMessage = serde_json::from_slice(&msg)?;
        if let ServerMessage::Update {
            permuter_id,
            update,
            ..
        } = msg
        {
            // let mut m = state.m.lock().unwrap();
            let mut server_state = server_state.lock().unwrap();

            // If we get back a message referring to a since-removed permuter,
            // no need to do anything.
            if let Some(job) = server_state.jobs.get_mut(&permuter_id) {
                match update {
                    ServerUpdate::InitDone { .. } => {
                        job.state = JobState::Loaded;
                        // TODO
                    }
                    ServerUpdate::InitFailed { .. } => {
                        job.state = JobState::Failed;
                        // TODO
                    }
                    ServerUpdate::Result { .. } => {
                        // TODO: send result on to client
                    }
                }
            }
        }

        // Try requesting more work by sending a message to the writer thread.
        // If the queue is full (because the writer thread is blocked on a
        // send), drop the request to avoid an unbounded backlog.
        if let Err(TrySendError::Closed(_)) = more_work_tx.try_send(()) {
            break;
        }
    }
    Ok(())
}

async fn server_write(
    port: &mut WritePort<'_>,
    server_state: &Mutex<ServerState>,
    state: &State,
    mut more_work_rx: mpsc::Receiver<()>,
) -> SimpleResult<()> {
    loop {
        enum ToSend {
            Work(PermuterWork),
            Add(Arc<Permuter>),
            Remove,
        }

        let mut wait_for: Option<oneshot::Receiver<()>> = None;
        let (perm_id, to_send) = 'choose_work: loop {
            if let Some(rx) = wait_for {
                rx.await.unwrap();
            }
            let mut m = state.m.lock().unwrap();
            let mut server_state = server_state.lock().unwrap();

            // If possible, send a new permuter.
            if let Some((&perm_id, perm)) = m
                .permuters
                .iter()
                .filter(|(&perm_id, _)| !server_state.jobs.contains_key(&perm_id))
                .next()
            {
                server_state.jobs.insert(
                    perm_id,
                    Job {
                        state: JobState::Loading,
                        energy: 0.0,
                    },
                );
                break (perm_id, ToSend::Add(perm.permuter.clone()));
            }

            // If none, find an existing one to work on, or to remove.
            let mut best_cost = 0.0;
            let mut best: Option<(u64, &mut Job)> = None;
            for (&perm_id, job) in server_state.jobs.iter_mut() {
                if let Some(perm) = m.permuters.get(&perm_id) {
                    if matches!(job.state, JobState::Loaded) && !perm.stale {
                        if best.is_none() || job.energy < best_cost {
                            best_cost = job.energy;
                            best = Some((perm_id, job));
                        }
                    }
                } else {
                    server_state.jobs.remove(&perm_id);
                    break 'choose_work (perm_id, ToSend::Remove);
                }
            }

            let (perm_id, job) = match best {
                None => {
                    // Nothing to work on! Register to be notified when something happens and go to
                    // sleep.
                    let (tx, rx) = oneshot::channel();
                    m.wake_on_more_work.push(tx);
                    wait_for = Some(rx);
                    continue;
                }
                Some(tup) => tup,
            };

            let perm = m.permuters.get_mut(&perm_id).unwrap();
            let work = match perm.work_queue.pop_front() {
                None => {
                    // Chosen permuter is out of work. Ask it for more, and mark it as
                    // stale. When it goes unstale all sleeping writers will be notified.
                    // TODO: ask for more work
                    perm.stale = true;
                    wait_for = None;
                    continue;
                }
                Some(work) => work,
            };

            let min_energy = job.energy;
            job.energy += perm.energy_add;

            // Adjust energies to be around zero, to avoid problems with float
            // imprecision, and to ensure that new permuters that come in with
            // energy zero will fit the schedule.
            for job in server_state.jobs.values_mut() {
                job.energy -= min_energy;
            }

            break (perm_id, ToSend::Work(work));
        };

        match to_send {
            ToSend::Work(PermuterWork { seed }) => {
                port.write_json(&json!({
                    "type": "work",
                    "permuter": perm_id,
                    "seed": seed,
                }))
                .await?;
            }
            ToSend::Add(permuter) => {
                port.write_json(&json!({
                    "type": "add",
                    "permuter": perm_id,
                    "data": &*permuter,
                }))
                .await?;
                port.write_compressed(permuter.source.as_bytes()).await?;
                port.write_compressed(&permuter.target_o_bin).await?;
            }
            ToSend::Remove => {
                port.write_json(&json!({
                    "type": "remove",
                    "permuter": perm_id,
                }))
                .await?;
            }
        }

        if matches!(more_work_rx.recv().await, None) {
            break;
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

    let (more_work_tx, more_work_rx) = mpsc::channel(SERVER_WORK_QUEUE_SIZE);

    let server_state = Mutex::new(ServerState {
        min_priority: data.min_priority,
        jobs: HashMap::new(),
    });

    let id = {
        let mut m = state.m.lock().unwrap();
        m.servers.insert(ConnectedServer {
            min_priority: data.min_priority,
            num_cpus: data.num_cpus,
        })
    };

    let r = tokio::try_join!(
        server_read(&mut read_port, &server_state, state, more_work_tx),
        server_write(&mut write_port, &server_state, state, more_work_rx)
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
            m.permuters.insert(
                id,
                ActivePermuter {
                    permuter: permuter.into(),
                    work_queue: VecDeque::new(),
                    stale: false,
                    energy_add,
                },
            );
        }
    }

    // TODO: do work

    {
        let mut m = state.m.lock().unwrap();
        for id in perm_ids {
            m.permuters.remove(&id);
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

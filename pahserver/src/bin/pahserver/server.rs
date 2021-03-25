use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot;

use crate::port::{ReadPort, WritePort};
use crate::{ConnectServerData, ConnectedServer, Permuter, PermuterWork, State};
use pahserver::db::UserId;
use pahserver::util::SimpleResult;

const SERVER_WORK_QUEUE_SIZE: usize = 100;

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

enum ToSend {
    Work(PermuterWork),
    Add(Arc<Permuter>),
    Remove,
}

async fn choose_work(server_state: &Mutex<ServerState>, state: &State) -> (u64, ToSend) {
    let mut wait_for: Option<oneshot::Receiver<()>> = None;
    loop {
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
            return (perm_id, ToSend::Add(perm.permuter.clone()));
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
                return (perm_id, ToSend::Remove);
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

        return (perm_id, ToSend::Work(work));
    }
}

async fn send_work(port: &mut WritePort<'_>, perm_id: u64, to_send: ToSend) -> SimpleResult<()> {
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
    };
    Ok(())
}

async fn server_write(
    port: &mut WritePort<'_>,
    server_state: &Mutex<ServerState>,
    state: &State,
    mut more_work_rx: mpsc::Receiver<()>,
) -> SimpleResult<()> {
    loop {
        let (perm_id, to_send) = choose_work(server_state, state).await;
        send_work(port, perm_id, to_send).await?;
        if matches!(more_work_rx.recv().await, None) {
            break;
        }
    }
    Ok(())
}

pub(crate) async fn handle_connect_server<'a>(
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

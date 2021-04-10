use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{mpsc, mpsc::error::TrySendError, watch, Notify};

use crate::db::UserId;
use crate::port::{ReadPort, WritePort};
use crate::stats;
use crate::util::SimpleResult;
use crate::{
    ConnectServerData, ConnectedServer, PermuterData, PermuterId, PermuterResult, PermuterWork,
    ServerUpdate, State, HEARTBEAT_TIME,
};

const SERVER_WORK_QUEUE_SIZE: usize = 100;
const TIME_US_GUESS: f64 = 100_000.0;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    NeedWork,
    Update {
        permuter: PermuterId,
        time_us: f64,
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
    jobs: HashMap<PermuterId, Job>,
}

async fn server_read(
    port: &mut ReadPort<'_>,
    who_id: &UserId,
    who_name: &str,
    server_state: &Mutex<ServerState>,
    state: &State,
    more_work_tx: mpsc::Sender<()>,
) -> SimpleResult<()> {
    loop {
        let msg = port.recv().await?;
        let msg: ServerMessage = serde_json::from_slice(&msg)?;
        let mut log_new = false;
        let mut more_work = true;
        if let ServerMessage::Update {
            permuter: perm_id,
            mut update,
            time_us,
        } = msg
        {
            if let ServerUpdate::Result {
                ref mut compressed_source,
                has_source: true,
                ..
            } = &mut update
            {
                *compressed_source = Some(port.recv().await?);
            }
            let mut m = state.m.lock().unwrap();
            let mut server_state = server_state.lock().unwrap();

            // If we get back a message referring to a since-removed permuter,
            // no need to do anything.
            if let Some(job) = server_state.jobs.get_mut(&perm_id) {
                if let Some(perm) = m.permuters.get_mut(&perm_id) {
                    job.energy -= perm.energy_add * TIME_US_GUESS;
                    job.energy += perm.energy_add * time_us;

                    match update {
                        ServerUpdate::InitDone { .. } => {
                            job.state = JobState::Loaded;
                            log_new = true;
                        }
                        ServerUpdate::InitFailed { .. } => {
                            job.state = JobState::Failed;
                        }
                        ServerUpdate::Disconnect { .. } => {
                            job.state = JobState::Failed;
                            more_work = false;
                        }
                        ServerUpdate::Result { .. } => {}
                    }
                    perm.send_result(PermuterResult::Result(
                        who_id.clone(),
                        who_name.to_string(),
                        update,
                    ));
                }
            }
        }

        if log_new {
            state
                .log_stats(stats::Record::ServerNewFunction {
                    server: who_id.clone(),
                })
                .await?;
        }

        if more_work {
            // Try requesting more work by sending a message to the writer thread.
            // If the queue is full (because the writer thread is blocked on a
            // send), drop the request to avoid an unbounded backlog.
            if let Err(TrySendError::Closed(_)) = more_work_tx.try_send(()) {
                panic!("work chooser must not close except on error");
            }
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ToSend {
    Work(PermuterWork),
    Add {
        client_id: UserId,
        client_name: String,
        data: Arc<PermuterData>,
    },
    Remove,
}

#[derive(Serialize)]
struct Work {
    permuter: PermuterId,
    #[serde(flatten)]
    to_send: ToSend,
}

async fn choose_work(server_state: &Mutex<ServerState>, state: &State) -> Work {
    let mut wait_for = None;
    loop {
        if let Some(waiter) = wait_for {
            waiter.await;
        }

        let mut m = state.m.lock().unwrap();
        let mut server_state = server_state.lock().unwrap();

        // If possible, send a new permuter.
        if let Some((&perm_id, perm)) = m
            .permuters
            .iter()
            .find(|(&perm_id, _)| !server_state.jobs.contains_key(&perm_id))
        {
            server_state.jobs.insert(
                perm_id,
                Job {
                    state: JobState::Loading,
                    energy: 0.0,
                },
            );
            return Work {
                permuter: perm_id,
                to_send: ToSend::Add {
                    client_id: perm.client_id.clone(),
                    client_name: perm.client_name.clone(),
                    data: perm.data.clone(),
                },
            };
        }

        // If none, find an existing one to work on, or to remove.
        let mut best_cost = 0.0;
        let mut best: Option<(PermuterId, &mut Job)> = None;
        let min_priority = server_state.min_priority;
        for (&perm_id, job) in server_state.jobs.iter_mut() {
            if let Some(perm) = m.permuters.get(&perm_id) {
                if matches!(job.state, JobState::Loaded)
                    && !perm.stale
                    && perm.priority >= min_priority
                    && (best.is_none() || job.energy < best_cost)
                {
                    best_cost = job.energy;
                    best = Some((perm_id, job));
                }
            } else {
                server_state.jobs.remove(&perm_id);
                return Work {
                    permuter: perm_id,
                    to_send: ToSend::Remove,
                };
            }
        }

        let (perm_id, job) = match best {
            None => {
                // Nothing to work on! Register to be notified when something
                // happens and go to sleep.
                wait_for = Some(state.new_work_notification.notified());
                continue;
            }
            Some(tup) => tup,
        };

        let perm = m.permuters.get_mut(&perm_id).unwrap();
        let work = match perm.work_queue.pop_front() {
            None => {
                // Chosen permuter is out of work. Ask it for more, and mark it
                // as stale. When it goes unstale all sleeping writers will be
                // notified.
                perm.send_result(PermuterResult::NeedWork);
                perm.stale = true;
                wait_for = None;
                continue;
            }
            Some(work) => work,
        };
        perm.semaphore.release();

        let min_energy = job.energy;
        job.energy += perm.energy_add * TIME_US_GUESS;

        // Adjust energies to be around zero, to avoid problems with float
        // imprecision, and to ensure that new permuters that come in with
        // energy zero will fit the schedule.
        for job in server_state.jobs.values_mut() {
            job.energy -= min_energy;
        }

        return Work {
            permuter: perm_id,
            to_send: ToSend::Work(work),
        };
    }
}

fn requires_response(work: &Work) -> bool {
    match work.to_send {
        ToSend::Work { .. } => true,
        ToSend::Add { .. } => true,
        ToSend::Remove => false,
    }
}

async fn server_choose_work(
    server_state: &Mutex<ServerState>,
    state: &State,
    mut more_work_rx: mpsc::Receiver<()>,
    choose_work_tx: mpsc::Sender<Work>,
    wrote_work: &Notify,
) -> SimpleResult<()> {
    loop {
        let work = choose_work(server_state, state).await;
        let req_work = requires_response(&work);
        choose_work_tx
            .send(work)
            .await
            .map_err(|_| ())
            .expect("writer must not close except on error");
        wrote_work.notified().await;
        if req_work {
            more_work_rx
                .recv()
                .await
                .expect("reader must not close except on error");
        }
    }
}

async fn send_heartbeat(port: &mut WritePort<'_>) -> SimpleResult<()> {
    port.send_json(&json!({
        "type": "heartbeat",
    }))
    .await
}

async fn send_work(port: &mut WritePort<'_>, work: &Work) -> SimpleResult<()> {
    port.send_json(&work).await?;
    if let ToSend::Add { ref data, .. } = work.to_send {
        port.send(&data.compressed_source).await?;
        port.send(&data.compressed_target_o_bin).await?;
    }
    Ok(())
}

async fn server_write(
    port: &mut WritePort<'_>,
    mut choose_work_rx: mpsc::Receiver<Work>,
    mut heartbeat_rx: watch::Receiver<()>,
    wrote_work: &Notify,
) -> SimpleResult<()> {
    loop {
        tokio::select! {
            work = choose_work_rx.recv() => {
                let work = work.expect("chooser must not close except on error");
                send_work(port, &work).await?;
                wrote_work.notify_one();
            }
            res = heartbeat_rx.changed() => {
                res.expect("heartbeat thread panicked");
                send_heartbeat(port).await?;
            }
        }
    }
}

pub(crate) async fn handle_connect_server<'a>(
    mut read_port: ReadPort<'a>,
    mut write_port: WritePort<'a>,
    who_id: &UserId,
    who_name: &str,
    state: &State,
    data: ConnectServerData,
) -> SimpleResult<()> {
    write_port
        .send_json(&json!({
            "docker_image": &state.docker_image,
            "heartbeat_interval": HEARTBEAT_TIME.as_secs(),
        }))
        .await?;

    let (more_work_tx, more_work_rx) = mpsc::channel(SERVER_WORK_QUEUE_SIZE);
    let (choose_work_tx, choose_work_rx) = mpsc::channel(1);
    let wrote_work = Notify::new();

    let mut server_state = Mutex::new(ServerState {
        min_priority: data.min_priority,
        jobs: HashMap::new(),
    });

    let id = state.m.lock().unwrap().servers.insert(ConnectedServer {
        min_priority: data.min_priority,
        num_cores: data.num_cores,
    });

    let r = tokio::try_join!(
        server_read(
            &mut read_port,
            who_id,
            who_name,
            &server_state,
            state,
            more_work_tx
        ),
        server_choose_work(
            &server_state,
            state,
            more_work_rx,
            choose_work_tx,
            &wrote_work
        ),
        server_write(
            &mut write_port,
            choose_work_rx,
            state.heartbeat_rx.clone(),
            &wrote_work
        )
    );

    {
        let mut m = state.m.lock().unwrap();
        for (&perm_id, job) in &server_state.get_mut().unwrap().jobs {
            if let JobState::Loaded = job.state {
                if let Some(perm) = m.permuters.get_mut(&perm_id) {
                    perm.send_result(PermuterResult::Result(
                        who_id.clone(),
                        who_name.to_string(),
                        ServerUpdate::Disconnect,
                    ));
                }
            }
        }

        m.servers.remove(id);
    }
    r?;
    Ok(())
}

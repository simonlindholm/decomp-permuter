use std::collections::VecDeque;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;

use crate::db::UserId;
use crate::flimsy_semaphore::FlimsySemaphore;
use crate::port::{ReadPort, WritePort};
use crate::stats;
use crate::util::SimpleResult;
use crate::{
    ConnectClientData, Permuter, PermuterId, PermuterResult, PermuterWork, ServerUpdate, State,
};

const CLIENT_MAX_QUEUES_SIZE: usize = 100;
const MIN_PRIORITY: f64 = 0.001;
const MAX_PRIORITY: f64 = 10.0;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientUpdate {
    Work(PermuterWork),
}

#[derive(Deserialize)]
struct ClientMessage {
    permuter_id: u32,
    update: ClientUpdate,
}

async fn client_read(
    port: &mut ReadPort<'_>,
    perm_meta: &[(PermuterId, String)],
    semaphore: &FlimsySemaphore,
    state: &State,
) -> SimpleResult<()> {
    loop {
        let msg = port.recv().await?;
        let msg: ClientMessage = serde_json::from_slice(&msg)?;
        let ClientUpdate::Work(work) = msg.update;
        let (perm_id, _) = perm_meta
            .get(msg.permuter_id as usize)
            .ok_or("Permuter index out of range")?;

        // Avoid the work and result queues growing indefinitely by restricting
        // their combined size with a semaphore.
        semaphore.acquire().await;

        let mut m = state.m.lock().unwrap();
        let perm = m.permuters.get_mut(perm_id).unwrap();
        perm.work_queue.push_back(work);
        if perm.stale {
            perm.stale = false;
            state.new_work_notification.notify_waiters();
        }
    }
}

async fn client_write(
    port: &mut WritePort<'_>,
    perm_meta: &[(PermuterId, String)],
    semaphore: &FlimsySemaphore,
    state: &State,
    mut result_rx: mpsc::UnboundedReceiver<(PermuterId, PermuterResult)>,
    client_id: &UserId,
) -> SimpleResult<()> {
    loop {
        let (perm_id, res) = result_rx.recv().await.unwrap();
        let local_perm_id = perm_meta.iter().position(|&(id, _)| id == perm_id).unwrap();
        let fn_name = &perm_meta[local_perm_id].1;
        semaphore.release();

        match res {
            PermuterResult::NeedWork => {
                port.send_json(&json!({
                    "type": "need_work",
                    "permuter": local_perm_id,
                }))
                .await?;
            }
            PermuterResult::Result(server_id, server_name, server_update) => {
                match server_update {
                    ServerUpdate::InitDone { score, hash } => {
                        port.send_json(&json!({
                            "type": "connect",
                            "permuter": local_perm_id,
                            "server": server_name,
                            "score": score,
                            "hash": hash,
                        }))
                        .await?;
                    }
                    ServerUpdate::InitFailed { reason } => {
                        port.send_json(&json!({
                            "type": "init_failed",
                            "permuter": local_perm_id,
                            "server": server_name,
                            "reason": reason,
                        }))
                        .await?;
                    }
                    ServerUpdate::Disconnect => {
                        port.send_json(&json!({
                            "type": "disconnect",
                            "permuter": local_perm_id,
                            "server": server_name,
                        }))
                        .await?;
                    }
                    ServerUpdate::Result {
                        score,
                        hash,
                        compressed_source,
                        ..
                    } => {
                        // TODO profiler, or generalized to extra fields, flattened?
                        // (serialize, in that case)
                        let has_source = compressed_source.is_some();
                        port.send_json(&json!({
                            "type": "result",
                            "permuter": local_perm_id,
                            "server": server_name,
                            "score": score,
                            "hash": hash,
                            "has_source": has_source,
                        }))
                        .await?;
                        if let Some(data) = compressed_source {
                            port.send(&data).await?;
                        }

                        let outcome = if !has_source {
                            stats::Outcome::Unhelpful
                        } else if score == 0 {
                            stats::Outcome::Matched
                        } else {
                            stats::Outcome::Improved
                        };
                        state
                            .log_stats(stats::Record::WorkDone {
                                server: server_id,
                                client: client_id.clone(),
                                fn_name: fn_name.to_string(),
                                outcome: outcome,
                            })
                            .await?;
                    }
                }
            }
        }
    }
}

pub(crate) async fn handle_connect_client<'a>(
    mut read_port: ReadPort<'a>,
    mut write_port: WritePort<'a>,
    who_id: &UserId,
    who_name: &str,
    state: &State,
    mut data: ConnectClientData,
) -> SimpleResult<()> {
    for permuter_data in &mut data.permuters {
        permuter_data.source = String::from_utf8(read_port.recv_compressed().await?)?;
        permuter_data.target_o_bin = read_port.recv_compressed().await?;
    }

    if !(MIN_PRIORITY <= data.priority && data.priority <= MAX_PRIORITY) {
        Err("Priority out of range")?;
    }
    if data.permuters.is_empty() {
        Err("No permuters")?;
    }

    let mut num_servers: u32 = 0;
    let mut cpu_capacity: u32 = 0;
    for server in state.m.lock().unwrap().servers.values() {
        if data.priority >= server.min_priority {
            num_servers += 1;
            cpu_capacity += server.num_cpus;
        }
    }

    write_port
        .send_json(&json!({
            "servers": num_servers,
            "cpus": cpu_capacity,
        }))
        .await?;

    for permuter_data in &data.permuters {
        state
            .log_stats(stats::Record::ClientNewFunction {
                client: who_id.clone(),
                fn_name: permuter_data.fn_name.clone(),
            })
            .await?;
    }

    let energy_add = (data.permuters.len() as f64) / data.priority;

    let (result_tx, result_rx) = mpsc::unbounded_channel();
    let semaphore = Arc::new(FlimsySemaphore::new(CLIENT_MAX_QUEUES_SIZE));

    let mut perm_meta = Vec::new();
    {
        let mut m = state.m.lock().unwrap();
        for permuter_data in data.permuters {
            let id = m.next_permuter_id;
            m.next_permuter_id += 1;
            perm_meta.push((id, permuter_data.fn_name.clone()));
            m.permuters.insert(
                id,
                Permuter {
                    data: permuter_data.into(),
                    client_id: who_id.clone(),
                    client_name: who_name.to_string(),
                    work_queue: VecDeque::new(),
                    result_tx: result_tx.clone(),
                    semaphore: semaphore.clone(),
                    stale: false,
                    priority: data.priority,
                    energy_add,
                },
            );
        }
        state.new_work_notification.notify_waiters();
    }

    let r = tokio::try_join!(
        client_read(&mut read_port, &perm_meta, &semaphore, state),
        client_write(
            &mut write_port,
            &perm_meta,
            &semaphore,
            state,
            result_rx,
            who_id
        )
    );

    {
        let mut m = state.m.lock().unwrap();
        for (id, _) in perm_meta {
            m.permuters.remove(&id);
        }
    }
    r?;
    Ok(())
}

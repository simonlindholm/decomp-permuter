use std::collections::VecDeque;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;

use crate::db::UserId;
use crate::flimsy_semaphore::FlimsySemaphore;
use crate::port::{ReadPort, WritePort};
use crate::stats;
use crate::util::SimpleResult;
use crate::{
    ConnectClientData, Permuter, PermuterData, PermuterId, PermuterResult, PermuterWork,
    ServerUpdate, State,
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
    update: ClientUpdate,
}

#[derive(Serialize)]
struct PermuterResultMessage<'a> {
    server: String,
    #[serde(flatten)]
    update: &'a ServerUpdate,
}

async fn client_read(
    port: &mut ReadPort<'_>,
    perm_id: &PermuterId,
    semaphore: &FlimsySemaphore,
    state: &State,
) -> SimpleResult<()> {
    loop {
        let msg = port.recv().await?;
        let msg: ClientMessage = serde_json::from_slice(&msg)?;
        let ClientUpdate::Work(work) = msg.update;

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
    fn_name: &str,
    semaphore: &FlimsySemaphore,
    state: &State,
    mut result_rx: mpsc::UnboundedReceiver<PermuterResult>,
    client_id: &UserId,
) -> SimpleResult<()> {
    loop {
        let res = result_rx.recv().await.unwrap();
        semaphore.release();

        match res {
            PermuterResult::NeedWork => {
                port.send_json(&json!({
                    "type": "need_work",
                }))
                .await?;
            }
            PermuterResult::Result(server_id, server_name, server_update) => {
                port.send_json(&PermuterResultMessage {
                    server: server_name,
                    update: &server_update,
                })
                .await?;

                if let ServerUpdate::Result {
                    score,
                    compressed_source,
                    ..
                } = server_update
                {
                    if let Some(ref data) = compressed_source {
                        port.send(data).await?;
                    }

                    let outcome = if compressed_source.is_none() {
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
                            outcome,
                        })
                        .await?;
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
    data: ConnectClientData,
) -> SimpleResult<()> {
    if !(MIN_PRIORITY <= data.priority && data.priority <= MAX_PRIORITY) {
        Err("Priority out of range")?;
    }

    let mut num_servers: u32 = 0;
    let mut num_cores: f64 = 0.0;
    for server in state.m.lock().unwrap().servers.values() {
        if data.priority >= server.min_priority {
            num_servers += 1;
            num_cores += server.num_cores;
        }
    }

    write_port
        .send_json(&json!({
            "servers": num_servers,
            "cores": num_cores,
        }))
        .await?;

    let permuter_data = read_port.recv().await?;
    let mut permuter_data: PermuterData = serde_json::from_slice(&permuter_data)?;
    permuter_data.source = String::from_utf8(read_port.recv_compressed().await?)?;
    permuter_data.target_o_bin = read_port.recv_compressed().await?;
    write_port.send_json(&json!({})).await?;

    state
        .log_stats(stats::Record::ClientNewFunction {
            client: who_id.clone(),
            fn_name: permuter_data.fn_name.clone(),
        })
        .await?;

    let energy_add = 1.0 / data.priority;
    let fn_name = permuter_data.fn_name.clone();

    let (result_tx, result_rx) = mpsc::unbounded_channel();
    let semaphore = Arc::new(FlimsySemaphore::new(CLIENT_MAX_QUEUES_SIZE));

    let perm_id = {
        let mut m = state.m.lock().unwrap();
        let id = m.next_permuter_id;
        m.next_permuter_id += 1;
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
        state.new_work_notification.notify_waiters();
        id
    };

    let r = tokio::try_join!(
        client_read(&mut read_port, &perm_id, &semaphore, state),
        client_write(
            &mut write_port,
            &fn_name,
            &semaphore,
            state,
            result_rx,
            who_id
        )
    );

    state.m.lock().unwrap().permuters.remove(&perm_id);
    r?;
    Ok(())
}

use std::collections::VecDeque;

use serde::Deserialize;
use serde_json::json;

use crate::port::{ReadPort, WritePort};
use crate::{ConnectClientData, Permuter, PermuterWork, State};
use pahserver::db::UserId;
use pahserver::util::SimpleResult;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientUpdate {
    Work {
        #[serde(flatten)]
        work: PermuterWork,
    },
}

#[derive(Deserialize)]
struct ClientMessage {
    permuter_id: u32,
    update: ClientUpdate,
}

async fn client_read(port: &mut ReadPort<'_>, perm_ids: &[u64], state: &State) -> SimpleResult<()> {
    loop {
        let msg = port.read().await?;
        let msg: ClientMessage = serde_json::from_slice(&msg)?;
        let ClientUpdate::Work { work } = msg.update;
        let perm_id = perm_ids
            .get(msg.permuter_id as usize)
            .ok_or("Permuter index out of range")?;
        let mut m = state.m.lock().unwrap();
        let perm = m.permuters.get_mut(perm_id).unwrap();
        perm.work_queue.push_back(work);
        if perm.stale {
            perm.stale = false;
            m.wake_sleepers();
        }
    }
}

async fn client_write(_port: &mut WritePort<'_>, _state: &State) -> SimpleResult<()> {
    // TODO
    // statistics
    Ok(())
}

pub(crate) async fn handle_connect_client<'a>(
    mut read_port: ReadPort<'a>,
    mut write_port: WritePort<'a>,
    _who: &UserId,
    state: &State,
    mut data: ConnectClientData,
) -> SimpleResult<()> {
    for permuter_data in &mut data.permuters {
        permuter_data.source = String::from_utf8(read_port.read_compressed().await?)?;
        permuter_data.target_o_bin = read_port.read_compressed().await?;
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
        .write_json(&json!({
            "servers": num_servers,
            "cpus": cpu_capacity,
        }))
        .await?;

    // TODO: validate that priority is sane
    let energy_add = (data.permuters.len() as f64) / data.priority;

    let mut perm_ids = Vec::new();
    {
        let mut m = state.m.lock().unwrap();
        for permuter_data in data.permuters {
            let id = m.next_permuter_id;
            m.next_permuter_id += 1;
            perm_ids.push(id);
            m.permuters.insert(
                id,
                Permuter {
                    data: permuter_data.into(),
                    work_queue: VecDeque::new(),
                    result_queue: VecDeque::new(),
                    stale: false,
                    priority: data.priority,
                    energy_add,
                },
            );
        }
        m.wake_sleepers();
    }

    let r = tokio::try_join!(
        client_read(&mut read_port, &perm_ids, state),
        client_write(&mut write_port, state)
    );

    {
        let mut m = state.m.lock().unwrap();
        for id in perm_ids {
            m.permuters.remove(&id);
        }
    }
    r?;
    Ok(())
}

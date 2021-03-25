use std::collections::VecDeque;

use serde_json::json;

use crate::port::{ReadPort, WritePort};
use crate::{ActivePermuter, ConnectClientData, State};
use pahserver::db::UserId;
use pahserver::util::SimpleResult;

pub(crate) async fn handle_connect_client<'a>(
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

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;

use pahserver::db::DB;
use pahserver::util::SimpleResult;

const SAVE_INTERVAL: Duration = Duration::from_secs(30);

pub enum SaveType {
    Delayed,
    Immediate,
}

struct InnerSaveableDB {
    db: DB,
    stale: bool,
    save_chan: mpsc::UnboundedSender<SaveType>,
}

#[derive(Clone)]
pub struct SaveableDB(Arc<RwLock<InnerSaveableDB>>);

async fn save_db_loop(db: SaveableDB, save_channel: &mut mpsc::UnboundedReceiver<SaveType>) -> SimpleResult<()> {
    loop {
        match save_channel.recv().await {
            None => return Ok(()),
            Some(SaveType::Immediate) => {},
            Some(SaveType::Delayed) => {
                // Wait for SAVE_INTERVAL or until we receive an Immediate save.
                let _ = timeout(SAVE_INTERVAL, async {
                    loop {
                        match save_channel.recv().await {
                            None | Some(SaveType::Immediate) => { break },
                            Some(SaveType::Delayed) => {},
                        };
                    }
                }).await;
            },
        };

        // Would be good to clear the queue in case more messages have stacked
        // up past an Immediate, but try_recv() is temporarily dead
        // (https://github.com/tokio-rs/tokio/issues/3350). Oh well, doesn't
        // matter much in practice.

        // Mark the DB as non-stale, to start receiving save messages again.
        {
            let mut inner = db.0.write().unwrap();
            inner.stale = false;
        }

        // Actually do the save. (TODO)
        {
            let inner = db.0.read().unwrap();
            println!("Save! {:?}", &inner.db);
        }
    }
}

impl SaveableDB {
    pub fn open(filename: &str) -> SimpleResult<SaveableDB> {
        let db_file = std::fs::File::open(filename)?;
        let db: DB = serde_json::from_reader(&db_file)?;

        let (save_tx, mut save_rx) = mpsc::unbounded_channel();

        let saveable_db = SaveableDB(Arc::new(RwLock::new(InnerSaveableDB {
            db,
            stale: false,
            save_chan: save_tx,
        })));

        let db2 = saveable_db.clone();

        tokio::spawn(async move {
            if let Err(e) = save_db_loop(db2, &mut save_rx).await {
                eprintln!("Failed to save! {:?}", e);
                std::process::exit(1);
            }
        });

        Ok(saveable_db)
    }

    pub fn read<T>(&self, callback: impl FnOnce(&DB) -> T) -> T {
        let inner = self.0.read().unwrap();
        callback(&inner.db)
    }

    pub fn write<T>(&self, callback: impl FnOnce(&mut DB) -> T, save_type: SaveType) -> T {
        let mut inner = self.0.write().unwrap();
        let ret = callback(&mut inner.db);
        if matches!(save_type, SaveType::Immediate) || !inner.stale {
            inner.save_chan.send(save_type).map_err(|_| ()).expect("Failed to send message to save task");
        }
        inner.stale = true;
        ret
    }
}

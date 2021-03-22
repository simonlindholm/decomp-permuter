use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{Nonce, PrecomputedKey};
use std::convert::TryInto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};

use pahserver::util::SimpleResult;

pub struct ReadPort<'a> {
    read_half: ReadHalf<'a>,
    key: PrecomputedKey,
    nonce: u64,
}

impl<'a> ReadPort<'a> {
    pub fn new(read_half: ReadHalf<'a>, key: &PrecomputedKey) -> Self {
        ReadPort {
            read_half,
            key: key.clone(),
            nonce: 0,
        }
    }

    pub async fn read(&mut self) -> SimpleResult<Box<[u8]>> {
        let len = self.read_half.read_u64().await?;
        if len >= (1 << 48) {
            Err("Unreasonable packet length")?
        }
        let mut buffer = vec![0; len.try_into()?];
        self.read_half.read_exact(&mut buffer[..]).await?;
        let nonce = nonce_from_u64(self.nonce);
        self.nonce += 2;
        let data =
            box_::open_precomputed(&buffer, &nonce, &self.key).map_err(|()| "Failed to decrypt")?;
        Ok(data.into())
    }
}

pub struct WritePort<'a> {
    write_half: WriteHalf<'a>,
    key: PrecomputedKey,
    nonce: u64,
}

impl<'a> WritePort<'a> {
    pub fn new(write_half: WriteHalf<'a>, key: &PrecomputedKey) -> Self {
        WritePort {
            write_half,
            key: key.clone(),
            nonce: 1,
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) -> SimpleResult<()> {
        let nonce = nonce_from_u64(self.nonce);
        self.nonce += 2;
        let data = box_::seal_precomputed(bytes, &nonce, &self.key);
        self.write_half.write_u64(data.len() as u64).await?;
        self.write_half.write(&data[..]).await?;
        Ok(())
    }

    pub async fn write_json(&mut self, value: &serde_json::Value) -> SimpleResult<()> {
        self.write(&serde_json::to_vec(value)?).await
    }
}

fn nonce_from_u64(num: u64) -> Nonce {
    let nonce_bytes = [[0; 8], [0; 8], num.to_be_bytes()].concat();
    Nonce::from_slice(&nonce_bytes).unwrap()
}

/*
class Port(abc.ABC):
    def send_json(self, msg: dict) -> None:
        """Send a message in the form of a JSON dict, potentially blocking."""
        self.send(json.dumps(msg).encode("utf-8"))

    def receive_json(self) -> dict:
        """Read a message in the form of a JSON dict, blocking."""
        ret = json.loads(self.receive())
        if not isinstance(ret, dict):
            # We always pass dictionaries as messages and no other data types,
            # to ensure future extensibility. (Other types are rare in
            # practice, anyway.)
            raise ValueError("Top-level JSON value must be a dictionary")
        return ret
*/

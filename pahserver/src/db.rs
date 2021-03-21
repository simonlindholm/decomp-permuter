use std::collections::HashMap;
use std::convert::TryInto;

use hex::FromHex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use sodiumoxide::crypto::sign;

// TODO const generics
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct HexString([u8; 32]);

impl Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<HexString, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let string = String::deserialize(deserializer)?;
        let val = Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string()))?;
        Ok(HexString(
            val.try_into()
                .map_err(|_| Error::custom("string must be 32 bytes"))?,
        ))
    }
}

pub type UserId = HexString;

impl From<sign::PublicKey> for UserId {
    fn from(key: sign::PublicKey) -> UserId {
        HexString(key.as_ref().try_into().unwrap())
    }
}

impl From<UserId> for sign::PublicKey {
    fn from(id: UserId) -> sign::PublicKey {
        sign::PublicKey::from_slice(&id.0).unwrap()
    }
}

impl From<UserId> for sign::Seed {
    fn from(id: UserId) -> sign::Seed {
        sign::Seed::from_slice(&id.0).unwrap()
    }
}

#[derive(Debug, Deserialize_tuple, Serialize_tuple)]
pub struct Stats {
    pub iterations: u64,
    pub improvements: u64,
    pub matches: u64,
}

impl Default for Stats {
    fn default() -> Stats {
        Stats {
            iterations: 0,
            improvements: 0,
            matches: 0,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub trusted_by: Option<UserId>,
    pub name: String,
    pub client_stats: Stats,
    pub server_stats: Stats,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DB {
    pub users: HashMap<UserId, User>,
    pub func_stats: HashMap<String, Stats>,
    pub total_stats: Stats,
}

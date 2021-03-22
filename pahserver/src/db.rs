use std::collections::HashMap;
use std::convert::TryInto;

use hex::FromHex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use sodiumoxide::crypto::sign;

// TODO const generics
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct ByteString([u8; 32]);

impl ByteString {
    fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    fn from_hex(string: &str) -> Result<ByteString, &'static str> {
        Ok(ByteString(
            Vec::from_hex(&string)
                .map_err(|_| "not a valid hex string")?
                .try_into()
                .map_err(|_| "string must be 32 bytes".into())?
        ))
    }
}

impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ByteString {
    fn deserialize<D>(deserializer: D) -> Result<ByteString, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let string = String::deserialize(deserializer)?;
        Ok(ByteString::from_hex(&string).map_err(|e| Error::custom(e))?)
    }
}

pub type UserId = ByteString;

impl UserId {
    pub fn from_pubkey(key: &sign::PublicKey) -> UserId {
        ByteString(key.as_ref().try_into().unwrap())
    }

    pub fn to_pubkey(&self) -> sign::PublicKey {
        sign::PublicKey::from_slice(&self.0).unwrap()
    }
}

impl ByteString {
    pub fn to_seed(&self) -> sign::Seed {
        sign::Seed::from_slice(&self.0).unwrap()
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

use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes::randombytes;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    sodiumoxide::init().map_err(|()| "Failed to initialize cryptography library")?;

    let server_seed = sign::Seed::from_slice(&randombytes(32)[..]).unwrap();
    let client_seed = sign::Seed::from_slice(&randombytes(32)[..]).unwrap();

    let (server_pub_key, _) = sign::keypair_from_seed(&server_seed);
    let (_client_pub_key, _) = sign::keypair_from_seed(&client_seed);

    // set up database

    println!(
        "Setup successful!\n\n\
        Put the following in the server's config.toml:\n\n\
        priv_seed = \"{}\"\n\n\
        Put the following in the root client's pah.conf:\n\n\
        secret_key = \"{}\"\n\
        auth_public_key = \"{}\"\n\
        auth_server = \"https://server.example:port\"",
        hex::encode(server_seed),
        hex::encode(client_seed),
        hex::encode(server_pub_key)
    );
    Ok(())
}

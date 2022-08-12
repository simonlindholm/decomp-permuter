# controller

This directory contains code for the central permuter@home controller server,
written in Rust. All p@h traffic passes through here.

If you just want to run a regular p@h client or worker, you don't need to care about this.

To setup your own copy of the controller server:

- Install Rust and (for the libsodium dependency) GCC.
- Run `cargo build --release`.
- Run `./target/release/pahserver setup --db path/to/database.json` and follow
  the instructions there. This will set the `priv_seed` part of `config.toml`, and
  set up an initial trusted client. The rest of `config.toml` can be copied from
  `config_example.toml`. These settings include a field for the Docker image to use
  to run `compile.sh` scripts within. For an example Dockerfile that works for
  this, see https://github.com/decompals/pah-docker.
- Start the server with:
  ```
./target/release/pahserver run --listen-on 0.0.0.0:<port> --config config.toml --db path/to/database.json
```
and configure the system to run this at startup, e.g. via a systemd service:
```
[Unit]
Description=permuter@home controller
After=network.target

[Service]
ExecStart=/path/to/pahserver run --listen-on 0.0.0.0:12321 --db pah_db.json --config pah_config.toml
# After 2 seconds, the server has probably set up its network connection.
# (This allows e.g. a pah worker service to depend upon this one.)
ExecStartPost=/bin/sleep 2
WorkingDirectory=/path/to
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
```

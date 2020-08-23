# authserver

This directory contains code for the permuter@home central auth (authentication/authorization) server.
It is written in Erlang, and tested to work on Erlang/OTP 23.

If you just want to run a regular p@h server, you don't need to care about this.

To setup your own copy of the auth server:

- Install Erlang and rebar3 (https://www.rebar3.org/docs/getting-started).
- Copy `config/sys-example.config` to `config/sys.config`, changing it appropriately.
  `docker_image` should probably point to an image on Docker Hub instead of a local image.
- Run `rebar3 compile`.
- Run `./setup.erl` and follow the instructions there.
  This will set the `priv_seed` part of sys.config, and set up an initial trusted client.
- Set up a reverse proxy that forwards HTTPS traffic from an external port or route
  to HTTP for the port in sys.config, e.g. using Nginx or Traefik.
  If applicable, configure your firewall to let the external port through.
- Start the server with `./run.sh -daemon`, and configure the system to run this at startup.
  To get an interactive shell at this point, use `to_erl`.

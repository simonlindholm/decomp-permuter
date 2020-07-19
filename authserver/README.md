# authserver

This directory contains code for the permuter@home central auth (authentication/authorization) server.
It is written in Erlang, and tested to work on Erlang/OTP 23.

If you just want to run a regular p@h server, you don't need to care about this.

To setup your own copy of the auth server:

- Install Erlang and rebar3 (https://www.rebar3.org/docs/getting-started).
- Copy `config/sys-example.config` to `config/sys.config`, changing it appropriately.
  `docker_image` should probably point to an image on Docker Hub instead of a local image.
- Make a request to `http://localhost:<port>/setup` and follow the instructions there.
  This will set the `priv_seed` part of sys.config, and set up an initial trusted client.
- Set up a reverse proxy that forwards HTTPS traffic from an external port to HTTP for
  the port in sys.config, e.g. using Nginx or Traefik.
  If applicable, configure your firewall to let this port through.
- Set the server to run `./run.sh` on startup (with `-noshell -detached` if desired).

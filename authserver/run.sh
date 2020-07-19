#!/bin/sh
~/bin/rebar3 compile
erl -pa _build/default/lib/*/ebin -s authserver_app "$@" # -noshell -detached

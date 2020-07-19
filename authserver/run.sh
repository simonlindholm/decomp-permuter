#!/bin/sh
rebar3 compile
if [ "$1" = "-daemon" ]; then
    run_erl -daemon /tmp/ /tmp/ "exec erl -pa _build/default/lib/*/ebin -s authserver_app"
else
    erl -pa _build/default/lib/*/ebin -s authserver_app "$@"
fi

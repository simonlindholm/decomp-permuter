#!/bin/sh
rebar3 compile
CMDLINE="erl -pa _build/default/lib/*/ebin -s authserver_app -config config/sys.config $(cat config/vm.args)"
if [ "$1" = "-daemon" ]; then
    run_erl -daemon /tmp/ /tmp/ "exec $CMDLINE"
else
    $CMDLINE "$@"
fi

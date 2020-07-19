-module(route_root).

-export([init/2]).

init(Req, Opts) ->
    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        <<"Welcome to the decomp-permuter authserver.">>,
        Req
    ),
    {ok, Req2, Opts}.

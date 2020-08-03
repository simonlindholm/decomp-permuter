-module(route_pubkey).

-export([init/2]).

init(Req, Config) ->
    #{pubkey := PubKey} = Config,
    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        to_hex(PubKey),
        Req
    ),
    {ok, Req2, Config}.

to_hex(Binary) ->
    [io_lib:format("~2.16.0b", [X]) || <<X:8>> <= Binary].

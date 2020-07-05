-module(route_pubkey).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req, Opts) ->
    {ok, Seed} = application:get_env(?APPLICATION, priv_seed),
    KeyMap = enacl:sign_seed_keypair(Seed),
    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        to_hex(maps:get(public, KeyMap)),
        Req
    ),
    {ok, Req2, Opts}.

to_hex(Binary) ->
    [io_lib:format("~2.16.0b", [X]) || <<X:8>> <= Binary].

-module(route_pubkey).

-export([init/2]).

init(Req, Opts) ->
    {ok, Seed} = application:get_env(?APPLICATION, priv_seed),
    KeyMap = enacl:sign_seed_keypair(Seed),
    Req2 = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain">>},
        maps:get(public, KeyMap),
        Req),
    {ok, Req2, Opts}.

-module(route_docker).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req, Opts) ->
    {ok, Docker} = application:get_env(?APPLICATION, docker_image),
    {ok, Seed} = application:get_env(?APPLICATION, priv_seed),
    KeyMap = enacl:sign_seed_keypair(Seed),
    SignedMessage = enacl:sign(
        ["DOCKER:", Docker],
        maps:get(secret, KeyMap)
    ),

    Req2 = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain">>},
        SignedMessage,
        Req),
    {ok, Req2, Opts}.

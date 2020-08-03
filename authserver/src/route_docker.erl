-module(route_docker).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req, Config) ->
    #{privkey := PrivKey, docker_image := Docker} = Config,
    SignedMessage = crypto_util:sign_message("DOCKER", Docker, PrivKey),

    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        SignedMessage,
        Req
    ),
    {ok, Req2, Config}.

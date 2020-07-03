-module(route_docker).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req, Opts) ->
    {ok, Docker} = application:get_env(?APPLICATION, docker_image),
    SignedMessage = crypto_util:sign_message("DOCKER", Docker),

    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        SignedMessage,
        Req
    ),
    {ok, Req2, Opts}.

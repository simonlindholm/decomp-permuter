%%%-------------------------------------------------------------------
%% @doc authserver main function
%% @end
%%%-------------------------------------------------------------------

-module(authserver_app).

-behaviour(application).

-export([start/0, start/2, stop/1]).

-define(APPLICATION, authserver).

start(_StartType, _StartArgs) ->
    {ok, Pid} = authserver_sup:start_link(),

    {ok, Seed} = application:get_env(?APPLICATION, priv_seed),
    {ok, DockerImage} = application:get_env(?APPLICATION, docker_image),
    KeyMap = enacl:sign_seed_keypair(Seed),
    Config = #{
      docker_image => DockerImage,
      pubkey => maps:get(public, KeyMap),
      privkey => maps:get(secret, KeyMap)
    },

    Endpoints = [
        {"/", route_root, Config},
        {"/docker", route_docker, Config},
        {"/go-online", route_go_online, Config},
        {"/go-offline", route_go_offline, Config},
        {"/list-servers", route_list_servers, Config},
        {"/pubkey", route_pubkey, Config}
    ],
    Dispatch = cowboy_router:compile([{'_', Endpoints}]),

    TransOpts = [{ip, {0, 0, 0, 0}}, {port, 2938}],
    ProtoOpts = #{env => #{dispatch => Dispatch}},

    {ok, _} = cowboy:start_clear(my_http_listener, TransOpts, ProtoOpts),

    {ok, Pid}.

stop(_State) ->
    ok.

start() ->
    {ok, _} = application:ensure_all_started(authserver).

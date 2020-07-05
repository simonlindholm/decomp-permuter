%%%-------------------------------------------------------------------
%% @doc authserver main function
%% @end
%%%-------------------------------------------------------------------

-module(authserver_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    {ok, Pid} = authserver_sup:start_link(),
    online_users:start(),

    Dispatch =
        cowboy_router:compile([
            {
                '_',
                [
                    {"/", route_root, []},
                    {"/docker", route_docker, []},
                    {"/pubkey", route_pubkey, []},
                    {"/setup", route_setup, []},
                    {"/go-online", route_go_online, []},
                    {"/go-offline", route_go_offline, []}
                ]
            }
        ]),

    TransOpts = [{ip, {0, 0, 0, 0}}, {port, 2938}],
    ProtoOpts = #{env => #{dispatch => Dispatch}},

    {ok, _} = cowboy:start_clear(my_http_listener, TransOpts, ProtoOpts),

    {ok, Pid}.

stop(_State) ->
    ok.

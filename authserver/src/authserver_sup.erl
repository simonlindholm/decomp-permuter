%%%-------------------------------------------------------------------
%% @doc authserver top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(authserver_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SupFlags = #{},
    ChildSpecs = [
        #{
            id => online_users,
            start => {online_users, start_link, []}
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.

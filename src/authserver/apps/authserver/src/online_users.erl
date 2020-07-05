-module(online_users).

-behaviour(gen_server).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([start/0, put/3, get/1, delete/1, ls/0]).

% public functions
start() ->
    gen_server:start({local, online_users}, ?MODULE, [], []).

put(Pubkey, IP, Port) ->
    gen_server:call(?MODULE, {put, Pubkey, IP, Port}).

get(Pubkey) ->
    gen_server:call(?MODULE, {get, Pubkey}).

delete(Pubkey) ->
    gen_server:call(?MODULE, {delete, Pubkey}).

ls() ->
    gen_server:call(?MODULE, ls).

% gen_server callbacks
init(_Args) ->
    {ok, kv_db:new()}.

handle_call({put, Pubkey, IP, Port}, _From, State) ->
    NewState = kv_db:put(Pubkey, {IP, Port}, State),
    {reply, NewState, NewState};
handle_call({get, Pubkey}, _From, State) ->
    {reply, kv_db:get(Pubkey, State), State};
handle_call({delete, Pubkey}, _From, State) ->
    NewState = kv_db:delete(Pubkey, State),
    {reply, NewState, NewState};
handle_call(ls, _From, State) ->
    {reply, State, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

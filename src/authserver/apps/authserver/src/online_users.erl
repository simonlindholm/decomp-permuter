-module(online_users).

-behaviour(gen_server).

-export([init/1, handle_call/3, handle_cast/2]).
-export([start_link/0, put/3, get/1, delete/1, ls/0]).

% public functions
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

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
    {ok, dict:new()}.

handle_call({put, Pubkey, IP, Port}, _From, State) ->
    NewState = dict:store(Pubkey, {IP, Port}, State),
    {reply, ok, NewState};
handle_call({get, Pubkey}, _From, State) ->
    {reply, dict:fetch(Pubkey, State), State};
handle_call({delete, Pubkey}, _From, State) ->
    NewState = dict:erase(Pubkey, State),
    {reply, ok, NewState};
handle_call(ls, _From, State) ->
    Ret = [
        #{pubkey => Pubkey, ip => IP, port => Port}
        || {Pubkey, {IP, Port}} <- dict:to_list(State)
    ],
    {reply, Ret, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

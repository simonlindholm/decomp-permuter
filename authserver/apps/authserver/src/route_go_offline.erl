-module(route_go_offline).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req, Opts) ->
    {ok, #{pubkey := Pubkey}, Req2} =
        cowboy_req:read_and_match_urlencoded_body([pubkey], Req),

    online_users:delete(Pubkey),

    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        "",
        Req
    ),
    {ok, Req2, Opts}.

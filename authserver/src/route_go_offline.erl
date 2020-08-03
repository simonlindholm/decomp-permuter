-module(route_go_offline).

-export([init/2]).

init(Req, Config) ->
    {ok, #{pubkey := PubKey}, Req2} =
        cowboy_req:read_and_match_urlencoded_body([pubkey], Req),

    online_users:delete(PubKey),

    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        "",
        Req
    ),
    {ok, Req2, Config}.

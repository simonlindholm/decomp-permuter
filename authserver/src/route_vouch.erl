-module(route_vouch).

-include("db_records.hrl").

-define(APPLICATION, authserver).

-export([init/2]).

init(Req, Config) ->
    {ok,
        #{
            pubkey := ClientPubKey,
            auth := Auth,
            vouched_pubkey := VouchedPubKey,
            signed_nickname := SignedNickname
        },
        Req2} =
        cowboy_req:read_and_match_urlencoded_body([pubkey], Req),

    {ok, User} = db:find_user(ClientPubKey),
    crypto_util:verify_message(<<"AUTH">>, Auth, ClientPubKey),

    UserNick = crypto_util:verify_message(
        <<"NICK">>,
        User#user.signed_nickname,
        ClientPubKey
    ),

    VouchedNick = crypto_util:verify_message(<<"NICK">>, SignedNickname, VouchedPubKey),
    VouchedUser = #user{
        pubkey = VouchedPubKey,
        signed_nickname = SignedNickname,
        trusted_by = ClientPubKey
    },

    io:format("New user: ~s trusted by ~s~n", [VouchedNick, UserNick]),

    % TODO: respond differently to already added users
    db:add_user(VouchedUser),

    Req3 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        <<>>,
        Req2
    ),
    {ok, Req3, Config}.

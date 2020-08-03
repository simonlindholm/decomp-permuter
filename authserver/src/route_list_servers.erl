-module(route_list_servers).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req, Config) ->
    #{privkey := PrivKey} = Config,
    {ok, #{pubkey := ClientPubKey}, Req2} =
        cowboy_req:read_and_match_urlencoded_body([pubkey], Req),

    Servers = online_users:ls(),
    ServerList = [
        #{
            ip => list_to_binary(IP),
            port => Port,
            verification_key => iolist_to_binary(to_hex(PubKey)),
            nickname => list_to_binary(IP)
        }
        || #{ip := IP, port := Port, pubkey := PubKey} <- Servers
    ],

    {MegaSecs, Secs, _} = os:timestamp(),
    ValidFrom = MegaSecs * 1000000 + Secs - 30,
    ValidUntil = ValidFrom + 60,

    GrantInfo = jsone:encode(
        #{
            valid_from => ValidFrom,
            valid_until => ValidUntil,
            signed_nickname => <<>>
        }
    ),
    SignedMessage =
        crypto_util:sign_message("GRANT", [ClientPubKey, GrantInfo], PrivKey),
    Grant = base64:encode(SignedMessage),

    Response = jsone:encode(
        #{server_list => ServerList, grant => Grant, version => 1}
    ),
    SignedResponse =
        crypto_util:sign_message("SERVERLIST", Response, PrivKey),

    Req3 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        SignedResponse,
        Req2
    ),
    {ok, Req3, Config}.

to_hex(Binary) ->
    [io_lib:format("~2.16.0b", [X]) || <<X:8>> <= Binary].

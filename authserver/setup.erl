#!/usr/bin/env escript
%% -*- erlang -*-
%%! -pa _build/default/lib/enacl/ebin

-mode(compile). % to get decent stack traces

-include("src/db_records.hrl").

main() ->
    AuthSeed = enacl:randombytes(32),
    ClientSeed = enacl:randombytes(32),
    #{public := AuthPubKey} = enacl:sign_seed_keypair(AuthSeed),
    #{public := ClientPubKey, secret := ClientPrivKey} = enacl:sign_seed_keypair(ClientSeed),
    RootSignedNick = enacl:sign(<<"NICK:root">>, ClientPrivKey),

    ok = mnesia:create_schema([node()]),

    ok = mnesia:start(),

    {atomic, ok} = mnesia:create_table(user, [
        {attributes, record_info(fields, user)},
        {disc_copies, [node()]}
    ]),

    {atomic, ok} = mnesia:transaction(fun() ->
        mnesia:write(
          #user{
            pubkey = ClientPubKey,
            signed_nickname = RootSignedNick,
            trusted_by = <<>>
          }
        )
    end),

    io:format(<<
        "Setup successful!~n~n"
        "Put the following in the auth server's priv.config:~n~n"
        "{priv_seed, ~p}~n~n"
        "Put the following in the root client's pah.conf:~n~n"
        "secret_key = \"~s\"~n"
        "auth_server = \"https://server.example:port\"~n"
        "auth_public_key = \"~s\"~n"
    >>, [
        AuthSeed,
        to_hex(ClientSeed),
        to_hex(AuthPubKey)
    ]).

main(_) -> main().

to_hex(Binary) ->
    [io_lib:format("~2.16.0b", [X]) || <<X:8>> <= Binary].

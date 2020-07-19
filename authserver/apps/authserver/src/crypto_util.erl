-module(crypto_util).

-define(APPLICATION, authserver).

-export([sign_message/2, verify_message/3]).

sign_message(Prefix, Message) ->
    {ok, Seed} = application:get_env(?APPLICATION, priv_seed),
    KeyMap = enacl:sign_seed_keypair(Seed),
    SignedMessage = enacl:sign(
        [Prefix, ":", Message],
        maps:get(secret, KeyMap)
    ),
    SignedMessage.

verify_message(Prefix, SignedMessage, Key) ->
    {ok, Message} = enacl:sign_open(SignedMessage, Key),
    [Prefix, Suffix] = binary:split(Message, <<":">>),
    Suffix.

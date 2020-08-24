-module(crypto_util).

-export([sign_message/3, verify_message/3]).

sign_message(Prefix, Message, Key) when size(Key) =:= 32 ->
    SignedMessage = enacl:sign(
        [Prefix, ":", Message],
        Key
    ),
    SignedMessage.

verify_message(Prefix, SignedMessage, Key) when size(Key) =:= 32 ->
    {ok, Message} = enacl:sign_open(SignedMessage, Key),
    [Prefix, Suffix] = binary:split(Message, <<":">>),
    Suffix.

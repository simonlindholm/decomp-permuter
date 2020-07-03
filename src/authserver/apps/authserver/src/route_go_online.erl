-module(route_go_online).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req = #{method := <<"POST">>}, State) ->
    {IP, _} = cowboy_req:peer(Req),

    {ok, KeyValues, Req} = cowboy_req:read_urlencoded_body(Req),
    #{port := Port, pubkey := Pubkey} = KeyValues,

    {ok, PeerSocket} =
        gen_tcp:connect(
            IP,
            binary_to_integer(Port),
            [binary, {packet, 0}]
        ),

    Message = enacl:randombytes(32),
    SignedMessage = crypto_util:sign_message("AUTHPING", Message),

    ok = gen_tcp:send(PeerSocket, ["\xFF\xFF\xFF\xFF", SignedMessage]),

    SignedReceivedMessage = receive_data(PeerSocket, []),
    ReceivedMessage =
        crypto_util:verify_message(
            <<"AUTHPONG">>,
            SignedReceivedMessage,
            Pubkey
        ),
    Message = ReceivedMessage,

    % TODO: Tell in-memory DB about (IP, Port, Pubkey).

    Req2 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        <<"">>,
        Req
    ),
    {ok, Req2, State};
init(Req, State) ->
    Req2 = cowboy_req:reply(
        405,
        #{
            <<"allow">> => <<"POST">>
        },
        Req
    ),
    {ok, Req2, State}.

receive_data(Socket, SoFar) ->
    io:format("~p~n", [SoFar]),
    receive
        {tcp, Socket, Bin} ->
            receive_data(Socket, [Bin | SoFar]);
        {tcp_closed, Socket} ->
            list_to_binary(list:reverse(SoFar))
    end.

-module(route_go_online).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req = #{method := <<"POST">>}, State) ->
    {IPAddr, _} = cowboy_req:peer(Req),
    IP = inet:ntoa(IPAddr),

    {ok, #{port := Port, pubkey := Pubkey}, Req2} =
        cowboy_req:read_and_match_urlencoded_body(
            [{port, int}, pubkey],
            Req
        ),

    {ok, PeerSocket} =
        gen_tcp:connect(
            IP,
            Port,
            [binary, {packet, 0}]
        ),

    Message = enacl:randombytes(32),
    SignedMessage = crypto_util:sign_message(<<"AUTHPING">>, Message),

    ok = gen_tcp:send(PeerSocket, ["\xFF\xFF\xFF\xFF", SignedMessage]),

    SignedReceivedMessage = receive_data(PeerSocket, []),

    ReceivedMessage =
        crypto_util:verify_message(
            <<"AUTHPONG">>,
            SignedReceivedMessage,
            Pubkey
        ),
    Message = ReceivedMessage,

    online_users:put(Pubkey, IP, Port),

    Req3 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/plain">>},
        <<"">>,
        Req2
    ),
    {ok, Req3, State};
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
    receive
        {tcp, Socket, Bin} ->
            receive_data(Socket, [Bin | SoFar]);
        {tcp_closed, Socket} ->
            list_to_binary(lists:reverse(SoFar))
    end.

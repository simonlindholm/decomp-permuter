-module(route_go_online).

-define(APPLICATION, authserver).

-export([init/2]).

init(Req = #{method := <<"POST">>}, State) ->
    % try
    {IP, _} = cowboy_req:peer(Req),

    {ok, KeyValues, Req2} = cowboy_req:read_urlencoded_body(Req),
    Port = proplists:get_value(<<"port">>, KeyValues),
    Pubkey = proplists:get_value(<<"pubkey">>, KeyValues),

    {ok, PeerSocket} =
        gen_tcp:connect(
            inet:ntoa(IP),
            binary_to_integer(Port),
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
    {ok, Req3, State}

    % catch
    %     _:_:Stacktrace ->
    %         erlang:display(Stacktrace)
    % end
    ;

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
            list_to_binary(lists:reverse(SoFar))
    end.

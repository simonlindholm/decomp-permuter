-module(db).

-include("db_records.hrl").

-include_lib("stdlib/include/qlc.hrl").

-export([find_user/1, add_user/1]).

find_user(PubKey) ->
    {atomic, Ret} =
        mnesia:transaction(fun () ->
            qlc:q(
                [User || User <- mnesia:table(user), User#user.pubkey =:= PubKey]
            )
        end),
    case Ret of
        [User] -> {ok, User};
        [] -> not_found
    end.

add_user(User) when is_record(User, user) ->
    {atomic, Ret} =
        mnesia:transaction(fun () ->
            mnesia:write(User)
        end),
    Ret.

-module(kv_db).

-type db() :: [].
-type results() :: nonempty_list({Key::binary(), Value::term()}).
-type err() :: {'error', string()}.

-export_type([db/0, results/0, err/0]).
-export([new/0, put/3, get/2, delete/2, ls/1]).

-spec new() -> db().
new() -> [].

-spec put(Key::binary(), Value::term(), Db::db()) -> results().
put(Key, Value, []) ->
  [{Key, Value}];
put(Key, Value, [{Key, _} | Db]) ->
  [{Key, Value} | Db];
put(Key, Value, [Current | Db]) ->
  [Current | put(Key, Value, Db)].

-spec get(Key::binary(), Db::db()) -> term() | err().
get(Key, []) ->
  {error, "Key not found: " ++ binary_to_list(Key)};
get(Key, [{Key, Value} | _]) ->
  Value;
get(Key, [_ | Db]) ->
  get(Key, Db).

-spec delete(Key::binary(), Db::db()) -> (results() | nil()) | err().
delete(Key, []) ->
  {error, "Key not found: " ++ binary_to_list(Key)};
delete(Key, [{Key, _Value} | Db]) ->
  Db;
delete(Key, [Tuple | Db]) ->
  [Tuple | delete(Key, Db)].

-spec ls(db()) -> [{binary(), term()}, ...] | nil().
ls(Db) ->
  Db.
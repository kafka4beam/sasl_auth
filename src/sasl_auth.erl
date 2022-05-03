%% @doc
%% Wrapper for cyrus sasl library for GSSAPI mechanism support in erlang applications. Each function (except kinit) corresponds to
%% functions at libsasl2
%% @end
-module(sasl_auth).

%% API
-export([
    init/0,
    kinit/2,
    sasl_client_init/0,
    sasl_client_new/3,
    sasl_listmech/0,
    sasl_client_start/0,
    sasl_client_step/1,
    sasl_errdetail/0
]).
-on_load(init/0).

init() ->
    NifLib =
        case code:priv_dir(sasl_auth) of
            {error, bad_name} ->
                case code:which(?MODULE) of
                    Filename when is_list(Filename) ->
                        filename:join([filename:dirname(Filename), "../priv", "sasl_auth"]);
                    _ ->
                        filename:join("../priv", "sasl_auth")
                end;
            Dir ->
                filename:join(Dir, "sasl_auth")
        end,
    erlang:load_nif(NifLib, 0).

-spec kinit(Keytab :: binary(), Principal :: binary()) ->
    {ok, Result :: string()} | {error, Reason :: string()}.
kinit(_, _) -> exit(nif_library_not_loaded).

-spec sasl_client_init() -> SaslCode :: integer() | {error, Reason :: string()}.
sasl_client_init() -> exit(nif_library_not_loaded).

-spec sasl_client_new(ServiceName :: binary(), Host :: binary(), Principal :: binary()) ->
    SaslCode :: integer() | {error, Reason :: string()}.
sasl_client_new(_, _, _) -> exit(nif_library_not_loaded).

-spec sasl_listmech() -> SupportedMechs :: string() | {error, Reason :: string()}.
sasl_listmech() -> exit(nif_library_not_loaded).

-spec sasl_client_start() ->
    {SaslRes :: integer(), Token :: string()} | {error, Reason :: string()}.
sasl_client_start() -> exit(nif_library_not_loaded).

-spec sasl_client_step(Token :: binary()) ->
    {SaslRes :: integer(), Token :: string()} | {error, Reason :: string()}.
sasl_client_step(_) -> exit(nif_library_not_loaded).

-spec sasl_errdetail() -> ErrorDescription :: string().
sasl_errdetail() -> exit(nif_library_not_loaded).

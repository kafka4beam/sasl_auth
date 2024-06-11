%% @doc
%% Wrapper for cyrus sasl library for GSSAPI mechanism support in erlang applications. Each function (except kinit) corresponds to
%% functions at libsasl2
%% @end
-module(sasl_auth).

%% API
-export([
    init/0,
    kinit/2,
    client_new/3,
    client_listmech/1,
    client_start/1,
    client_step/2,
    client_done/1,
    server_new/2,
    server_start/2,
    server_step/2,
    server_done/1
]).

-on_load(init/0).

-define(SASL_CODES, #{
    0 => sasl_ok,
    1 => sasl_continue,
    2 => sasl_interact,
    -1 => sasl_fail,
    -2 => sasl_nomem,
    -3 => sasl_bufover,
    -4 => sass_nomech,
    -5 => sasl_badprot,
    -6 => sasl_notdone,
    -7 => sasl_badparam,
    -8 => sasl_tryagain,
    -9 => sasl_badmac,
    -10 => sasl_badserv,
    -11 => sasl_wrongmech,
    -12 => sasl_notinit,
    -13 => sasl_badauth,
    -14 => sasl_noauthz,
    -15 => sasl_tooweak,
    -16 => sasl_encrypt,
    -17 => sasl_trans,
    -18 => sasl_expired,
    -19 => sasl_disabled,
    -20 => sasl_nouser,
    -21 => sasl_pwlock,
    -22 => sasl_nochange,
    -23 => sasl_badvers,
    -24 => sasl_unavail,
    -26 => sasl_noverify,
    -27 => sasl_weakpass,
    -28 => sasl_nouserpass,
    -29 => sasl_need_old_passwd,
    -30 => sasl_constraint_violat,
    -32 => sasl_badbinding,
    -100 => sasl_configerr
}).

-type state() :: reference().
-type keytab_path() :: file:filename_all().
-type principal() :: binary().
-type service_name() :: binary().
-type host() :: binary().
-type available_mechs() :: [binary()].

-type sasl_code() ::
    sasl_badserv
    | sasl_noverify
    | sasl_weakpass
    | sasl_badauth
    | sasl_tooweak
    | sasl_nomem
    | sasl_need_old_passwd
    | sasl_badprot
    | sasl_expired
    | sasl_nouser
    | sasl_badbinding
    | sasl_badvers
    | sasl_configerr
    | sasl_noauthz
    | sasl_ok
    | sasl_nouserpass
    | sasl_notdone
    | sasl_notinit
    | sasl_trans
    | sasl_interact
    | sasl_bufover
    | sasl_pwlock
    | sasl_constraint_violat
    | sasl_continue
    | sasl_fail
    | sasl_encrypt
    | sasl_badparam
    | sasl_badmac
    | sasl_tryagain
    | sasl_unavail
    | sasl_wrongmech
    | sasl_nochange
    | sasl_disabled
    | sass_nomech
    | unknown.

-spec init() ->
    ok | {error, {load_failed | bad_lib | load | reload | upgrade | old_code, Text :: string()}}.
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
    RetVal = erlang:load_nif(NifLib, 0),
    ErrorMsg =
        case RetVal of
            {error, _Reason} = LoadError ->
                Msg =
                    io_lib:format(
                        "Loading of sasl_auth's shared library failed.\n"
                        "The reason for this is probably missing dependencies or that a\n"
                        "dependency has a different version than the ones sasl_auth was compiled with.\n"
                        "Please see https://github.com/kafka4beam/sasl_auth for information\n"
                        "about sasl_auth's dependencies."
                        "SASL/GSSAPI (Kerberos) authentication will probably not work.\n"
                        "\n"
                        "Return Value for erlang:load_nif(~s, 0):\n"
                        "~p",
                        [NifLib, LoadError]
                    ),
                persistent_term:put(
                    sasl_auth_shared_lib_load_error_msg,
                    {on_load_error_info, LoadError, Msg}
                ),
                Msg;
            _ ->
                ok
        end,
    case application:get_env(sasl_auth, fail_on_load_if_load_unsuccessful, false) of
        _ when RetVal =:= ok ->
            ok;
        true ->
            logger:error(ErrorMsg),
            RetVal;
        false ->
            %% We will return ok but log a warning message with logger
            logger:warning(ErrorMsg),
            RetVal,
            ok
    end.

-spec kinit(KeyTabPath :: keytab_path(), Principal :: principal()) ->
    ok | {error, {binary(), integer(), binary()}}.
kinit(KeyTabPath, Principal) ->
    sasl_kinit(null_terminate(KeyTabPath), null_terminate(Principal)).

-spec client_new(ServiceName :: service_name(), Host :: host(), Principal :: principal()) ->
    {ok, state()}
    | {error, sasl_code()}.
client_new(ServiceName, Host, Principal) ->
    ServiceName0 = null_terminate(ServiceName),
    Host0 = null_terminate(Host),
    Principal0 = null_terminate(Principal),
    case sasl_client_new(ServiceName0, Host0, Principal0) of
        {ok, _} = Ret ->
            Ret;
        {error, Code} ->
            {error, code_to_atom(Code)}
    end.

-spec client_listmech(State :: state()) ->
    {ok, available_mechs()} | {error, {sasl_code(), binary()}}.
client_listmech(State) ->
    case sasl_listmech(State) of
        {ok, Mechs} ->
            {ok, binary:split(Mechs, <<" ">>, [global])};
        {error, {Code, Detail}} ->
            {error, {code_to_atom(Code), strip_null_terminate(Detail)}}
    end.

-spec client_start(State :: state()) ->
    {ok, {sasl_code(), binary()}} | {error, {sasl_code(), binary()}}.
client_start(State) ->
    case sasl_client_start(State) of
        {ok, {Code, Token}} ->
            {ok, {code_to_atom(Code), Token}};
        {error, {Code, Detail}} ->
            {error, {code_to_atom(Code), strip_null_terminate(Detail)}}
    end.

-spec client_step(state(), binary()) ->
    {ok, {sasl_code(), binary()}} | {error, {sasl_code(), binary()}}.
client_step(State, Token) ->
    case sasl_client_step(State, Token) of
        {ok, {Code, MaybeNewToken}} ->
            {ok, {code_to_atom(Code), MaybeNewToken}};
        {error, {Code, Detail}} ->
            {error, {code_to_atom(Code), strip_null_terminate(Detail)}}
    end.

-spec client_done(state()) -> ok.
client_done(State) ->
    sasl_client_done(State).

-spec server_new(ServiceName :: service_name(), Principal :: principal()) ->
    {ok, state()}
    | {error, sasl_code()}.
server_new(ServiceName, Principal) ->
    ServiceName0 = null_terminate(ServiceName),
    Principal0 = null_terminate(Principal),
    case sasl_server_new(ServiceName0, Principal0) of
        {ok, _} = Ret ->
            Ret;
        {error, Code} ->
            {error, code_to_atom(Code)}
    end.

-spec server_start(State :: state(), binary()) ->
    {ok, {sasl_code(), binary()}} | {error, {sasl_code(), binary()}}.
server_start(State, ClientIn) ->
    case sasl_server_start(State, ClientIn) of
        {ok, {Code, Token}} ->
            {ok, {code_to_atom(Code), Token}};
        {error, {Code, Detail}} ->
            {error, {code_to_atom(Code), strip_null_terminate(Detail)}}
    end.

-spec server_step(state(), binary()) ->
    {ok, {sasl_code(), binary()}} | {error, {sasl_code(), binary()}}.
server_step(State, Token) ->
    case sasl_server_step(State, Token) of
        {ok, {Code, MaybeNewToken}} ->
            {ok, {code_to_atom(Code), MaybeNewToken}};
        {error, {Code, Detail}} ->
            {error, {code_to_atom(Code), strip_null_terminate(Detail)}}
    end.

-spec server_done(state()) -> ok.
server_done(State) ->
    sasl_server_done(State).

code_to_atom(Code) ->
    maps:get(Code, ?SASL_CODES, unknown).

null_terminate(Bin) ->
    iolist_to_binary([Bin, 0]).

strip_null_terminate(Bin) ->
    case binary:split(Bin, <<0>>) of
        [X, _] ->
            X;
        [X] ->
            X
    end.

sasl_kinit(_, _) -> not_loaded(?LINE).

sasl_client_new(_Service, _Host, _Principal) -> not_loaded(?LINE).

sasl_listmech(_State) -> not_loaded(?LINE).

sasl_client_start(_State) -> not_loaded(?LINE).

sasl_client_step(_State, _Token) -> not_loaded(?LINE).

sasl_client_done(_State) -> not_loaded(?LINE).

sasl_server_new(_Service, _Principal) -> not_loaded(?LINE).

sasl_server_start(_State, _Token) -> not_loaded(?LINE).

sasl_server_step(_State, _Token) -> not_loaded(?LINE).

sasl_server_done(_State) -> not_loaded(?LINE).

not_loaded(Line) ->
    erlang:nif_error(
        {not_loaded, [
            {module, ?MODULE},
            {line, Line},
            persistent_term:get(
                sasl_auth_shared_lib_load_error_msg,
                no_load_error_saved
            )
        ]}
    ).

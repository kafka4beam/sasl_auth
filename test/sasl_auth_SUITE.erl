-module(sasl_auth_SUITE).

-compile(export_all).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
        kinit_test,
        simple_test,
        kinit_keytab_fail_test,
        kinit_invalid_principal_test,
        concurrency_test,
        delay_run,
        concurrency_delay_run_test,
        sasl_client_step_invalid_state_test,
        sasl_client_fail_to_start_test,
        validate_client_start,
        sasl_client_step_invalid_token_test
    ].

init_per_suite(Config) ->
    UserKeyTab = get_env(user_keytab, "SASL_AUTH_TEST_KEY_TAB"),
    UserRealm = get_env(user_realm, "SASL_AUTH_TEST_REALM"),
    UserPrincipal = get_env(user_principal, "SASL_AUTH_TEST_PRINCIPAL"),
    ServerHost = get_env(server_host, "SASL_AUTH_TEST_SERVER_HOST"),
    ServiceKeyTab = get_env(service_keytab, "SASL_AUTH_KAFKA_KEY_TAB"),
    ServiceName = get_env(service_principal, "SASL_AUTH_KAFKA_PRINCIPAL"),
    Service = {service, <<"kafka">>},

    ok = sasl_auth:kinit(element(2, UserKeyTab), element(2, UserPrincipal)),
    %% Unable to kinit with service keytab here, only one keytab can be kinit at a time.

    [
        UserKeyTab, UserPrincipal, ServerHost, UserRealm,
        ServiceKeyTab, ServiceName,
        Service | Config
    ].

end_per_suite(_Config) ->
    ok.

kinit_test(Config) ->
    KeyTab = ?config(user_keytab, Config),
    Principal = ?config(user_principal, Config),
    ok = sasl_auth:kinit(KeyTab, Principal).

simple_test(Config) ->
    {ok, CliConn} = setup_default_client(Config),
    {ok, [_ | _]} = sasl_auth:client_listmech(CliConn),
    {ok, {sasl_continue, ClientToken}} = sasl_auth:client_start(CliConn),
    {ok, SrvConn} = setup_default_service(Config),
    {ok, {sasl_continue, ServerToken}} = sasl_auth:server_start(SrvConn, ClientToken),
    {ok, {sasl_continue, ClientToken1}} = sasl_auth:client_step(CliConn, ServerToken),
    {ok, {sasl_continue, ServerToken2}} = sasl_auth:server_step(SrvConn, ClientToken1),
    {ok, {sasl_ok, ClientToken2}} = sasl_auth:client_step(CliConn, ServerToken2),
    {ok, {sasl_ok, ServerToken3}} = sasl_auth:server_step(SrvConn, ClientToken2),
    ?assertEqual(<<"">>, ServerToken3),
    ok = sasl_auth:server_done(SrvConn),
    ok = sasl_auth:client_done(CliConn),
    ok.

delay_run(Config) ->
    {ok, State} = setup_default_client(Config),
    timer:sleep(rand:uniform(100)),
    {ok, [_ | _]} = sasl_auth:client_listmech(State),
    {ok, {sasl_continue, _Token}} = sasl_auth:client_start(State),
    _ = sasl_auth:client_step(State, <<"token">>).

kinit_keytab_fail_test(Config) ->
    Principal = ?config(user_principal, Config),
    Result = sasl_auth:kinit(<<"keytab">>, Principal),
    ?assertMatch({error, {<<"krb5_get_init_creds_keytab">>, _, _}}, Result).

kinit_invalid_principal_test(Config) ->
    KeyTab = ?config(user_keytab, Config),
    ?assertMatch({error, {<<"krb5_parse_name">>, _, _Msg}}, sasl_auth:kinit(KeyTab, <<"\\">>)).

sasl_client_fail_to_start_test(_) ->
    ?assertError(badarg, sasl_auth:client_start(make_ref())).

validate_client_start(Config) ->
    {ok, State} = setup_default_client(Config),
    {ok, {sasl_continue, Token}} = sasl_auth:client_start(State),
    ?assert(is_binary(Token)).

sasl_client_step_invalid_state_test(Config) ->
    {ok, _State} = setup_default_client(Config),
    ?assertError(badarg, sasl_auth:client_step(make_ref(), list_to_binary("Token"))).

sasl_client_step_invalid_token_test(Config) ->
    {ok, State} = setup_default_client(Config),
    Result = sasl_auth:client_step(State, list_to_binary("Token")),
    ?assertMatch({error, {sass_nomech, <<"No MECH set">>}}, Result).

concurrency_test(Config) ->
    NumTimes = lists:seq(1, 100),
    Self = self(),
    Pids = [spawn(fun() -> do_run(Self, Config) end) || _ <- NumTimes],
    Results = await_results(Pids, []),
    OrigLength = length(Results),
    %% There should be no duplicate references.
    NewLength = length(lists:usort(Results)),
    ?assertMatch(OrigLength, NewLength).

%% This may be redundant now per the above test
concurrency_delay_run_test(Config) ->
    [spawn(fun() -> delay_run(Config) end) || _ <- lists:seq(1, 10)].

%% Helpers

do_run(Pid, Config) ->
    {ok, State} = setup_default_client(Config),
    {ok, [_ | _]} = sasl_auth:client_listmech(State),
    %UniqueMechs = lists:usort(AvailableMechs),
    %?assertMatch([<<"ANONYMOUS">>,<<"EXTERNAL">>,<<"GS2-KRB5">>,<<"GSS-SPNEGO">>,<<"GSSAPI">>], UniqueMechs),
    {ok, {_, Token}} = sasl_auth:client_start(State),
    {error, {sasl_fail, _}} = sasl_auth:client_step(State, <<"token">>),
    timer:sleep(rand:uniform(100)),
    Pid ! {self(), #{state => State, token => Token}},
    ok.

await_results([], Acc) ->
    Acc;
await_results([Worker | Pids], Acc) ->
    receive
        {Worker, Result} ->
            await_results(Pids, [Result | Acc])
    after 5000 -> error
    end.

setup_default_client(Config) ->
    Principal = ?config(user_principal, Config),
    Host = ?config(server_host, Config),
    Service = ?config(service, Config),
    sasl_auth:client_new(Service, Host, Principal).

setup_default_service(Config) ->
    Service = ?config(service, Config),
    ServiceKeyTab = ?config(service_keytab, Config),
    ServicePrincipal = ?config(service_principal, Config),
    Host = ?config(server_host, Config),
    ok = sasl_auth:kinit(ServiceKeyTab, ServicePrincipal),
    sasl_auth:server_new(Service, ServicePrincipal, Host).

get_env(Key, Env) ->
    case list_to_binary(os:getenv(Env, "")) of
        <<"">> -> ct:fail(<<"Environment variable not set: ", (list_to_binary(Key))/binary>>);
        Value -> {Key, Value}
    end.

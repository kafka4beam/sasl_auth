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
    KeyTab = list_to_binary(os:getenv("SASL_AUTH_TEST_KEY_TAB", "")),
    Principal = list_to_binary(os:getenv("SASL_AUTH_TEST_PRINCIPAL", "")),
    Host = list_to_binary(os:getenv("SASL_AUTH_TEST_HOST", "")),
    Service = <<"kafka">>,

    case {KeyTab, Principal, Host} of
        {K, P, H} when K =/= <<"">> andalso P =/= <<"">> andalso H =/= <<"">> ->
            ok;
        _ ->
            ct:fail(
                "One of SASL_AUTH_TEST_KEY_TAB, SASL_AUTH_TEST_PRINCIPAL, and SASL_AUTH_TEST_HOST not set in env"
            )
    end,
    ok = sasl_auth:kinit(KeyTab, Principal),

    [{keytab, KeyTab}, {principal, Principal}, {host, Host}, {service, Service} | Config].

end_per_suite(_Config) ->
    ok.

kinit_test(Config) ->
    KeyTab = ?config(keytab, Config),
    Principal = ?config(principal, Config),
    ok = sasl_auth:kinit(KeyTab, Principal).

simple_test(Config) ->
    {ok, State} = setup_default_client(Config),
    {ok, [_ | _]} = sasl_auth:client_listmech(State),
    {ok, _} = sasl_auth:client_start(State).

delay_run(Config) ->
    {ok, State} = setup_default_client(Config),
    timer:sleep(rand:uniform(100)),
    {ok, [_ | _]} = sasl_auth:client_listmech(State),
    {ok, {sasl_continue, _Token}} = sasl_auth:client_start(State),
    _ = sasl_auth:client_step(State, <<"token">>).

kinit_keytab_fail_test(Config) ->
    Principal = ?config(principal, Config),
    Result = sasl_auth:kinit(<<"keytab">>, Principal),
    ?assertMatch({error, {<<"krb5_get_init_creds_keytab">>, _, _}}, Result).

kinit_invalid_principal_test(Config) ->
    KeyTab = ?config(keytab, Config),
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
    Principal = ?config(principal, Config),
    Host = ?config(host, Config),
    Service = ?config(service, Config),
    sasl_auth:client_new(Service, Host, Principal).

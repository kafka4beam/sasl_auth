-module(int_test).

-feature(maybe_expr, enable).

-export([start/1]).

start(N) ->
    L = lists:seq(1, N),
    lists:foreach(fun(I) -> proc_lib:spawn(fun() -> do_start(I) end) end, L).

do_start(I) ->
    case atom_to_list(node()) of
        "cli" ++ _ ->
            run_cli(I);
        "srv" ++ _ ->
            run_srv(I)
    end.

run_cli(I) ->
    Service = env("SERVICE"),
    maybe
        ok = sasl_auth:kinit("cli.keytab", env("CLI_PRINC"), "MEMORY:test"),
        io:format("done kinit~n", []),
        {ok, C} ?= sasl_auth:client_new(Service, env("SRV"), env("CLI_PRINC"), env("CLI_NAME")),
        Pid = wait_for_server(I),
        {ok, AvaialbeMecs} ?= sasl_auth:client_listmech(C),
        true = lists:member(<<"GSSAPI">>, AvaialbeMecs),
        {ok, {sasl_continue, CT1}} ?= sasl_auth:client_start(C),
        ST1 = send_and_recv(Pid, ct1, CT1),
        io:format("got st1~n", []),
        {ok, {sasl_continue, CT2}} ?= sasl_auth:client_step(C, ST1),
        ST2 = send_and_recv(Pid, ct2, CT2),
        io:format("got st2~n", []),
        {ok, {sasl_ok, CT3}} ?= sasl_auth:client_step(C, ST2),
        io:format("sasl_ok: ~0p~n", [CT3]),
        _ = erlang:send(Pid, {self(), CT3}),
        io:format("sent: ct3~n", []),
        timer:sleep(2_000),
        ok = sasl_auth:client_done(C)
    else
        Error ->
            io:format("~0p~n", [Error])
    end,
    ok.

run_srv(I) ->
    Service = env("SERVICE"),
    maybe
        %% server always init from default keytab anyway,
        %% so doing kinit here doesn't really do anything
        %ok ?= sasl_auth:kinit("srv.keytab", env("SRV_PRINC")),
        {ok, S} ?= sasl_auth:server_new(Service, env("SRV_PRINC")),
        catch register(srv_name(I), self()),
        {Pid, CT1} =
            receive
                {P0, T0} ->
                    {P0, T0}
            after
                10_000 ->
                    error(timeout)
            end,
        io:format("got ct1: ~p~n", [CT1]),
        {ok, {sasl_continue, ST1}} ?= sasl_auth:server_start(S, CT1),
        CT2 = send_and_recv(Pid, st1, ST1),
        io:format("got ct2~n", []),
        {ok, {sasl_continue, ST2}} ?= sasl_auth:server_step(S, CT2),
        CT3 = send_and_recv(Pid, st2, ST2),
        io:format("got ct3~n", []),
        {ok, {sasl_ok, ST3}} ?= sasl_auth:server_step(S, CT3),
        io:format("sasl_ok: ~0p~n", [ST3]),
        <<>> = ST3,
        ok = sasl_auth:server_done(S)
    else
        Error ->
            io:format("~0p~n", [Error])
    end,
    ok.

env(Name) ->
    case os:getenv(Name) of
        false ->
            error({unknown_env, Name});
        "" ->
            error({unknown_env, Name});
        Val ->
            Val
    end.

send_and_recv(Remote, Tag, Token) ->
    Pid = self(),
    _ = erlang:send(Remote, {Pid, Token}),
    io:format("sent: ~0p~n", [Tag]),
    receive
        {_Pid, Reply} ->
            Reply
    after
        3000 ->
            error(timeout)
    end.

wait_for_server(I) ->
    case rpc:call(srv@srv, erlang, whereis, [srv_name(I)]) of
        Pid when is_pid(Pid) ->
            io:format("\n", []),
            Pid;
        _ ->
            timer:sleep(1000),
            io:format(".", []),
            wait_for_server(I)
    end.

srv_name(I) ->
    list_to_atom("srv" ++ integer_to_list(I)).

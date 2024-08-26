-module(int_test).

-feature(maybe_expr, enable).

-export([start/0, start/1, start/2]).

start() ->
    process_flag(trap_exit, true),
    start(1).

start(Count) ->
    start(Count, <<>>).

start(Count, CCname) ->
    Pids = case atom_to_list(node()) of
        "cli" ++ _ ->
            start_loop(fun(I) -> run_cli(I, CCname) end, Count);
        "srv" ++ _ ->
            start_loop(fun(I) -> run_srv(I, CCname) end, Count)
    end,
    wait_for_pids_exit(Pids).

start_loop(StartFn, Count) ->
    IDs = lists:seq(1, Count),
    lists:map(fun(I) -> spawn_link(fun() -> StartFn(I) end) end, IDs).

wait_for_pids_exit([]) ->
    ok;
wait_for_pids_exit([Pid | Pids]) ->
    receive
        {'EXIT', Pid, normal} ->
            wait_for_pids_exit(Pids);
        {'EXIT', Pid, Error} ->
            exit(Error)
    end.

run_cli(ID, CCname) ->
    Service = env("SERVICE"),
    maybe
        ok = sasl_auth:kinit("cli.keytab", env("CLI_PRINC"), CCname),
        io:format("[~p] done kinit~n", [ID]),
        {ok, C} ?= sasl_auth:client_new(Service, env("SRV"), env("CLI_PRINC"), env("CLI_NAME")),
        Pid = wait_for_server(srv_name(ID)),
        {ok, AvaialbeMecs} ?= sasl_auth:client_listmech(C),
        true = lists:member(<<"GSSAPI">>, AvaialbeMecs),
        {ok, {sasl_continue, CT1}} ?= sasl_auth:client_start(C),
        ST1 = send_and_recv(ID, Pid, ct1, CT1),
        io:format("[~p] got st1~n", [ID]),
        {ok, {sasl_continue, CT2}} ?= sasl_auth:client_step(C, ST1),
        ST2 = send_and_recv(ID, Pid, ct2, CT2),
        io:format("[~p] got st2~n", [ID]),
        {ok, {sasl_ok, CT3}} ?= sasl_auth:client_step(C, ST2),
        io:format("[~p] sasl_ok: ~0p~n", [ID, CT3]),
        _ = erlang:send(Pid, {self(), CT3}),
        io:format("[~p] sent: ct3~n", [ID]),
        timer:sleep(2_000),
        ok = sasl_auth:client_done(C)
    else
        Error ->
            io:format("[~p] ~0p~n", [ID, Error])
    end,
    ok.

run_srv(ID, _CCname) ->

    maybe
        %% server always init from default keytab anyway,
        %% so doing kinit here doesn't really do anything
        %ok ?= sasl_auth:kinit("srv.keytab", env("SRV_PRINC")),

        Service = env("SERVICE"),
        {ok, S} ?= sasl_auth:server_new(Service, env("SRV_PRINC")),
        register(srv_name(ID), self()),
        {Pid, CT1} =
            receive
                {P0, T0} ->
                    {P0, T0}
            after
                10_000 ->
                    error(timeout)
            end,
        io:format("[~p] got ct1: ~p~n", [ID, CT1]),
        {ok, {sasl_continue, ST1}} ?= sasl_auth:server_start(S, CT1),
        CT2 = send_and_recv(ID, Pid, st1, ST1),
        io:format("[~p] got ct2~n", [ID]),
        {ok, {sasl_continue, ST2}} ?= sasl_auth:server_step(S, CT2),
        CT3 = send_and_recv(ID, Pid, st2, ST2),
        io:format("[~p] got ct3~n", [ID]),
        {ok, {sasl_ok, ST3}} ?= sasl_auth:server_step(S, CT3),
        io:format("[~p] sasl_ok: ~0p~n", [ID, ST3]),
        <<>> = ST3,
        ok = sasl_auth:server_done(S)
    else
        Error ->
            io:format("[~p] ~0p~n", [ID, Error])
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

send_and_recv(ID, Remote, Tag, Token) ->
    Pid = self(),
    _ = erlang:send(Remote, {Pid, Token}),
    io:format("[~p] sent: ~0p~n", [ID, Tag]),
    receive
        {_Pid, Reply} ->
            Reply
    after
        3000 ->
            error(timeout)
    end.

wait_for_server(Name) ->
    case rpc:call(srv@srv, erlang, whereis, [Name]) of
        Pid when is_pid(Pid) ->
            io:format("\n", []),
            Pid;
        _ ->
            timer:sleep(1000),
            io:format(".", []),
            wait_for_server(Name)
    end.

srv_name(ID) ->
    list_to_atom("srv_" ++ integer_to_list(ID)).

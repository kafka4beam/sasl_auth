%%--------------------------------------------------------------------
%% Copyright (c) 2020-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(sasl_auth_scram_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(APP, sasl_auth).

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    %% Port program dir
    BinDir = filename:join([code:lib_dir(?APP),
                            "test/bin/",
                            hd(string:tokens(erlang:system_info(system_architecture), "-"))]),
    [{bin_dir, BinDir} | Config].

end_per_suite(_Config) ->
    application:stop(?APP).

all() -> [t_scram,
          t_scram_neg,
          t_interop_kpro_scram,
          t_interop_rustbase_scram_neg,
          t_interop_rustbase_scram,
          t_interop_kpro_scram_neg
         ].

t_scram(_) ->
    Username = <<"admin">>,
    Password = <<"public">>,
    IterationCount = 4096,
    Algorithm = sha256,

    {StoredKey, ServerKey, Salt} = sasl_auth_scram:generate_authentication_info(Password, #{algorithm => Algorithm, iteration_count => IterationCount}),
    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    ClientFirstMessage = sasl_auth_scram:client_first_message(Username),

    ct:pal("ClientFirst: ~p", [ClientFirstMessage]),

    {continue, ServerFirstMessage, ServerCache} =
        check_client_first_message(
            ClientFirstMessage,
            #{iteration_count => IterationCount,
              retrieve => RetrieveFun}
        ),

    ct:pal("ServerFirst: ~p~nStates:~p", [ServerFirstMessage, ServerCache]),
    {continue, ClientFinalMessage, ClientCache} =
        check_server_first_message(
            ServerFirstMessage,
            #{client_first_message => ClientFirstMessage,
              password => Password,
              algorithm => Algorithm}
        ),

    ct:pal("ClientFinal: ~p~n:State~p", [ClientFinalMessage, ClientCache]),
    {ok, ServerFinalMessage} =
        check_client_final_message(
            ClientFinalMessage, ServerCache#{algorithm => Algorithm}
        ),

    ct:pal("ServerFinal: ~p", [ServerFinalMessage]),
    ok = check_server_final_message(
        ServerFinalMessage, ClientCache#{algorithm => Algorithm}
    ).

t_scram_neg(_) ->
    Username = <<"admin">>,
    %% WHEN:  Client & Server using different password
    Password = <<"public">>,
    Password2 = <<"private">>,
    IterationCount = 4096,
    Algorithm = sha256,

    {StoredKey, ServerKey, Salt} = generate_authentication_info(Password, #{algorithm => Algorithm, iteration_count => IterationCount}),
    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    ClientFirstMessage = client_first_message(Username),

    ct:pal("ClientFirst: ~p", [ClientFirstMessage]),

    {continue, ServerFirstMessage, ServerCache} =
        check_client_first_message(
            ClientFirstMessage,
            #{iteration_count => IterationCount,
              retrieve => RetrieveFun}
        ),

    ct:pal("ServerFirst: ~p~nStates:~p", [ServerFirstMessage, ServerCache]),
    {continue, ClientFinalMessage, ClientCache} =
        check_server_first_message(
            ServerFirstMessage,
            #{client_first_message => ClientFirstMessage,
              password => Password2,
              algorithm => Algorithm}
        ),

    ct:pal("ClientFinal: ~p~n:State~p", [ClientFinalMessage, ClientCache]),
    %% THEN: validation failed
    ?assertEqual({error, 'other-error'},
        check_client_final_message(
            ClientFinalMessage, ServerCache#{algorithm => Algorithm}
        )).

%% @doc interop test with rustbase-scram
t_interop_rustbase_scram(Config) ->
    process_flag(trap_exit, true),
    PortProgram = ?config(bin_dir, Config) ++ "/scram_cli",
    Username = <<"user">>,
    Password = <<"123456">>,
    Algorithm = sha256,
    IterationCount = 4096,
    PortOpenArgs = [Username, Password, atom_to_binary(Algorithm)],

    {StoredKey, ServerKey, Salt}
        = generate_authentication_info(Password, #{algorithm => Algorithm,
                                                               iteration_count => IterationCount}),

    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    Port = open_port({spawn_executable, PortProgram}, [{line, 1024},
                                                       {args, PortOpenArgs},
                                                       use_stdio,
                                                       binary
                                                      ]),

    ClientFirstMessage = recv_from_port(Port),

    {continue, ServerFirstMessage, ServerCache} =
        check_client_first_message(
          ClientFirstMessage,
          #{iteration_count => IterationCount,
            retrieve => RetrieveFun}),

    send_to_port(Port, ServerFirstMessage),
    ClientFinalMessage = recv_from_port(Port),
    {ok, ServerFinalMessage} =
        check_client_final_message(
          ClientFinalMessage, ServerCache#{algorithm => Algorithm}
         ),
    send_to_port(Port, ServerFinalMessage),
    ?assertEqual(<<"AUTH OK">>, recv_from_port(Port)).


%% @doc interop test with rustbase-scram, negtive
t_interop_rustbase_scram_neg(Config) ->
    process_flag(trap_exit, true),
    PortProgram = ?config(bin_dir, Config) ++ "/scram_cli",
    Username = <<"user">>,
    %% WHEN:  Client & Server using different password
    Password = <<"123456">>,
    PortPassword = <<"234567">>,
    Algorithm = sha256,
    IterationCount = 4096,
    PortOpenArgs = [Username, PortPassword, atom_to_binary(Algorithm)],

    {StoredKey, ServerKey, Salt} =
        generate_authentication_info(Password,
                                                 #{algorithm => Algorithm,
                                                   iteration_count => IterationCount}),

    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    Port = open_port({spawn_executable, PortProgram}, [{line, 1024},
                                                       {args, PortOpenArgs},
                                                       use_stdio,
                                                       binary
                                                      ]),

    ClientFirstMessage = recv_from_port(Port),

    {continue, ServerFirstMessage, ServerCache} =
        check_client_first_message(
          ClientFirstMessage,
          #{iteration_count => IterationCount,
            retrieve => RetrieveFun}),

    send_to_port(Port, ServerFirstMessage),
    ClientFinalMessage = recv_from_port(Port),

    %% THEN: validation failed
    ?assertEqual({error, 'other-error'},
        check_client_final_message(
          ClientFinalMessage, ServerCache#{algorithm => Algorithm}
         )),
    erlang:port_close(Port).

%% @doc interop test with kpro_scram
t_interop_kpro_scram(_) ->
    load_kpro_scram(),
    Username = <<"user_kpro">>,
    Password = <<"kprokafka">>,
    Algorithm = sha256,
    IterationCount = 4096,
    {StoredKey, ServerKey, Salt} = generate_authentication_info(Password, #{algorithm => Algorithm, iteration_count => IterationCount}),

    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    Ctx = kpro_scram:init(sha256, Username, Password),
    ClientFirstMessage = kpro_scram:first(Ctx),

    {continue, ServerFirstMessage, ServerCache} =
        check_client_first_message(
          ClientFirstMessage,
          #{iteration_count => IterationCount,
            retrieve => RetrieveFun}),

    Ctx1 = kpro_scram:parse(Ctx, ServerFirstMessage),

    ClientFinalMessage = kpro_scram:final(Ctx1),
    {ok, ServerFinalMessage} =
        check_client_final_message(
          ClientFinalMessage, ServerCache#{algorithm => Algorithm}
         ),
    ?assertEqual(ok, kpro_scram:validate(Ctx1, ServerFinalMessage)).

%% @doc interop test with kpro_scram, negtive
t_interop_kpro_scram_neg(_) ->
    load_kpro_scram(),
    Username = <<"user_kpro">>,
    %% WHEN:  Client & Server using different password
    Password = <<"kprokafka">>,
    KproPassword = <<"prokafkak">>,
    Algorithm = sha256,
    IterationCount = 4096,
    {StoredKey, ServerKey, Salt} = generate_authentication_info(Password, #{algorithm => Algorithm, iteration_count => IterationCount}),

    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    Ctx = kpro_scram:init(sha256, Username, KproPassword),
    ClientFirstMessage = kpro_scram:first(Ctx),

    {continue, ServerFirstMessage, ServerCache} =
        check_client_first_message(
          ClientFirstMessage,
          #{iteration_count => IterationCount,
            retrieve => RetrieveFun}),

    Ctx1 = kpro_scram:parse(Ctx, ServerFirstMessage),

    ClientFinalMessage = kpro_scram:final(Ctx1),

    %% THEN: validation failed
    ?assertEqual({error, 'other-error'},
        check_client_final_message(
          ClientFinalMessage, ServerCache#{algorithm => Algorithm}
         )).

%% helpers
recv_from_port(Port) ->
    receive
        {Port, {data, {eol, Data}}} ->
            ct:pal("recv from Port: ~p", [Data]),
            Data;
        {Port, Unsupp} ->
            ct:fail("recv from Port but unsupported data: ~p", [Unsupp])
    after 10000 ->
            ct:fail("failed to recv from Port")
    end.

send_to_port(Port, RawData) when is_binary(RawData) ->
    ct:pal("sent to Port: ~p", [RawData]),
    Port ! {self(), {command, <<RawData/binary, "\n">>}}.


load_kpro_scram() ->
    {ok, {{"HTTP/1.1", 200, "OK"}, _Hdrs ,Body}}
        = httpc:request("https://raw.githubusercontent.com/kafka4beam/kafka_protocol/master/src/kpro_scram.erl"),
    file:write_file("/tmp/kpro_scram.erl", Body),
    {ok, kpro_scram} = c:nc("/tmp/kpro_scram.erl").

generate_authentication_info(Password, Opts) ->
    sasl_auth_scram:generate_authentication_info(Password, Opts).

client_first_message(Username) ->
    sasl_auth_scram:client_first_message(Username).

check_client_first_message(Msg, Opts) ->
    sasl_auth_scram:check_client_first_message(Msg, Opts).

check_client_final_message(Msg, Opts) ->
    sasl_auth_scram:check_client_final_message(Msg, Opts).

check_server_first_message(Msg, Opts) ->
    sasl_auth_scram:check_server_first_message(Msg, Opts).

check_server_final_message(Msg, Opts) ->
    sasl_auth_scram:check_server_final_message(Msg, Opts).

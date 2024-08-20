%%--------------------------------------------------------------------
%% Copyright (c) 2021-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-module(sasl_auth_scram).

-export([generate_authentication_info/2]).

-export([client_first_message/1]).

-export([ check_client_first_message/2
        , check_client_final_message/2
        , check_server_first_message/2
        , check_server_final_message/2
        ]).

-ifdef(TEST).
-compile(export_all).
-compile(nowarn_export_all).
-endif.

%%------------------------------------------------------------------------------
%% APIs
%%------------------------------------------------------------------------------

generate_authentication_info(Password, #{algorithm := Algorithm,
                                         iteration_count := IterationCount}) ->
    Salt = gen_salt(),
    SaltedPassword = salted_password(Algorithm, Password, Salt, IterationCount),
    ClientKey = client_key(Algorithm, SaltedPassword),
    ServerKey = server_key(Algorithm, SaltedPassword),
    StoredKey = stored_key(Algorithm, ClientKey),
    {StoredKey, ServerKey, Salt}.

client_first_message(Username) ->
    iolist_to_binary([gs2_header(), client_first_message_bare(Username)]).

%% SaltedPassword  := Hi(Normalize(password), salt, i)
%% ClientKey       := HMAC(SaltedPassword, "Client Key")
%% StoredKey       := H(ClientKey)
%% AuthMessage     := client-first-message-bare + "," +
%%                    server-first-message + "," +
%%                    client-final-message-without-proof
%% ClientSignature := HMAC(StoredKey, AuthMessage)
%% ClientProof     := ClientKey XOR ClientSignature
%% ServerKey       := HMAC(SaltedPassword, "Server Key")
%% ServerSignature := HMAC(ServerKey, AuthMessage)

check_client_first_message(ClientFirstMessage, #{iteration_count := IterationCount,
                                                 retrieve := RetrieveFun}) ->
    case parse_client_first_message(ClientFirstMessage) of
        {ok, #{username := Username,
               nonce := ClientNonce,
               gs2_cbind_flag := GS2CBindFlag}} ->
            case RetrieveFun(Username) of
                {error, _} ->
                    ignore;
                {ok, #{stored_key := _, server_key := _, salt := Salt} = Retrieved} ->
                    ClientFirstMessageBare = peek_client_first_message_bare(ClientFirstMessage),
                    ServerNonce = nonce(),
                    Nonce = iolist_to_binary([ClientNonce, ServerNonce]),
                    ServerFirstMessage = server_first_message(Nonce, Salt, IterationCount),
                    {continue, ServerFirstMessage, maps:merge(#{next_step                 => client_final,
                                                                client_first_message_bare => ClientFirstMessageBare,
                                                                server_first_message      => ServerFirstMessage,
                                                                nonce                     => Nonce,
                                                                gs2_cbind_flag            => GS2CBindFlag}, Retrieved)}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

check_client_final_message(ClientFinalmessage, #{client_first_message_bare := ClientFirstMessageBare,
                                                 server_first_message      := ServerFirstMessage,
                                                 stored_key                := StoredKey,
                                                 server_key                := ServerKey,
                                                 nonce                     := CachedNonce,
                                                 gs2_cbind_flag            := GS2CBindFlag,
                                                 algorithm                 := Algorithm}) ->
    case parse_client_final_message(ClientFinalmessage) of
        {ok, #{nonce := Nonce,
               proof := ClientProof,
               gs2_cbind_flag := GS2CBindFlag}} ->
            ClientFinalMessageWithoutProof = peek_client_final_message_without_proof(ClientFinalmessage),
            AuthMessage = iolist_to_binary([ ClientFirstMessageBare
                                           , ","
                                           , ServerFirstMessage
                                           , ","
                                           , ClientFinalMessageWithoutProof]),
            ClientSignature = hmac(Algorithm, StoredKey, AuthMessage),
            case iolist_size(ClientProof) =:= iolist_size(ClientSignature) of
                true ->
                    ClientKey = crypto:exor(ClientProof, ClientSignature),
                    case Nonce =:= CachedNonce andalso crypto:hash(Algorithm, ClientKey) =:= StoredKey of
                        true ->
                            ServerSignature = hmac(Algorithm, ServerKey, AuthMessage),
                            ServerFinalMessage = server_final_message(verifier, ServerSignature),
                            {ok, ServerFinalMessage};
                        false ->
                            {error, 'other-error'}
                    end;
                false ->
                    %% using a different algorithm
                    {error, 'bad-client-proof'}
            end;
        {ok, _} ->
            {error, 'channel-bindings-dont-match'};
        {error, Reason} ->
            {error, Reason}
    end.

check_server_first_message(ServerFirstMessage, #{client_first_message := ClientFirstMessage,
                                                 password             := Password,
                                                 algorithm            := Algorithm}) ->
    case parse_server_first_message(ServerFirstMessage) of
        {ok, #{nonce := Nonce,
               salt := Salt,
               iteration_count := IterationCount}} ->
            ClientFirstMessageBare = peek_client_first_message_bare(ClientFirstMessage),
            ClientFinalMessageWithoutProof = client_final_message_without_proof(Nonce),
            AuthMessage = iolist_to_binary([ ClientFirstMessageBare
                                           , ","
                                           , ServerFirstMessage
                                           , ","
                                           , ClientFinalMessageWithoutProof]),
            SaltedPassword = salted_password(Algorithm, Password, Salt, IterationCount),
            ClientKey = client_key(Algorithm, SaltedPassword),
            StoredKey = stored_key(Algorithm, ClientKey),
            ClientSignature = hmac(Algorithm, StoredKey, AuthMessage),
            ClientProof = crypto:exor(ClientKey, ClientSignature),
            {continue, client_final_message(Nonce, ClientProof),
                #{next_step                   => server_final,
                  password                    => Password,
                  client_first_message_bare   => ClientFirstMessageBare,
                  server_first_message        => ServerFirstMessage}};
        {error, Reason} ->
            {error, Reason}
    end.

check_server_final_message(ServerFinalMessage,
                           #{password                    := Password,
                             client_first_message_bare   := ClientFirstMessageBare,
                             server_first_message        := ServerFirstMessage,
                             algorithm                   := Algorithm}) ->
    case parse_server_final_message(ServerFinalMessage) of
        {ok, #{verifier := Verifier}} ->
            {ok, #{nonce := Nonce,
                   salt := Salt,
                   iteration_count := IterationCount}} = parse_server_first_message(ServerFirstMessage),
            ClientFinalMessageWithoutProof = client_final_message_without_proof(Nonce),
            AuthMessage = iolist_to_binary([ ClientFirstMessageBare
                                           , ","
                                           , ServerFirstMessage
                                           , ","
                                           , ClientFinalMessageWithoutProof]),
            SaltedPassword = salted_password(Algorithm, Password, Salt, IterationCount),
            ServerKey = server_key(Algorithm, SaltedPassword),
            case Verifier =:= hmac(Algorithm, ServerKey, AuthMessage) of
                true ->
                    ok;
                false ->
                    {error, 'other-error'}
            end;
        {ok, #{error := _Reason}} ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%%------------------------------------------------------------------------------
%% Internal functions
%%------------------------------------------------------------------------------

%% client-first-message
%% = gs2-cbind-flag "," [authzid] "," [reserved-mext ","] userame "," nonce ["," extensions]
parse_client_first_message(Bin) ->
    Structure = [ gs2_cbind_flag
                , authzid
                , reserved_mext
                , username
                , nonce
                , extensions],
    parse_attributes(Bin, Structure).

%% client-final-message
%% = channel-binding "," nonce ["," extensions] "," proof
parse_client_final_message(Bin) ->
    Structure = [ channel_binding
                , nonce
                , extensions
                , proof],
    parse_attributes(Bin, Structure).

%% server-first-message
%% = [reserved-mext ","] nonce "," salt "," iteration-count ["," extensions]
parse_server_first_message(Bin) ->
    Structure = [ reserved_mext
                , nonce
                , salt
                , iteration_count
                , extensions],
    parse_attributes(Bin, Structure).

%% server-final-message
%% = (server-error / verifier) ["," extensions]
parse_server_final_message(Bin) ->
    Structure = [ server_error_or_verifier
                , extensions],
    parse_attributes(Bin, Structure).

peek_client_first_message_bare(Bin) ->
    [_, One] = binary:split(Bin, <<",">>),
    [_, Two] = binary:split(One, <<",">>),
    Two.

peek_client_final_message_without_proof(Bin) ->
    [ClientFinalMessageWithoutProof | _] = binary:split(Bin, <<",p=">>, [trim_all]),
    ClientFinalMessageWithoutProof.

parse_attributes(Bin, Structure) when is_binary(Bin) ->
    Chunks = binary:split(Bin, <<",">>, [global]),
    parse_attributes(Chunks, Structure, #{}).

parse_attributes([], [], Acc) ->
    {ok, Acc};
parse_attributes(_, [extensions], Acc) ->
    {ok, Acc};
parse_attributes(Chunks, [extensions, proof], Acc) ->
    case skip_extensions(Chunks, fun parse_proof/2) of
        {ok, Attribute, []} ->
            {ok, maps:merge(Acc, Attribute)};
        {ok, _, _} ->
            {error, 'other-error'};
        {error, Reason} ->
            {error, Reason}
    end;
parse_attributes([<<"m=", _/binary>> | _], [reserved_mext | _], _) ->
    {error, 'extensions-not-supported'};
parse_attributes(Chunks, [reserved_mext | More], Acc) ->
    parse_attributes(Chunks, More, Acc);
parse_attributes([Chunk | More1], [AttrName | More2], Acc) ->
    case parse_attribute(AttrName, Chunk, Acc) of
        {ok, NAcc} ->
            parse_attributes(More1, More2, NAcc);
        {error, Reason} ->
            {error, Reason}
    end;
parse_attributes(_, _, _) ->
    {error, 'other-error'}.

parse_attribute(gs2_cbind_flag, Bin, Attributes) ->
    parse_gs2_cbind_flag(Bin, Attributes);
parse_attribute(authzid, Bin, Attributes) ->
    parse_authzid(Bin, Attributes);
parse_attribute(username, Bin, Attributes) ->
    parse_username(Bin, Attributes);
parse_attribute(nonce, Bin, Attributes) ->
    parse_nonce(Bin, Attributes);
parse_attribute(channel_binding, Bin, Attributes) ->
    parse_channel_binding(Bin, Attributes);
parse_attribute(cbind_data, Bin, Attributes) ->
    parse_cbind_data(Bin, Attributes);
parse_attribute(salt, Bin, Attributes) ->
    parse_salt(Bin, Attributes);
parse_attribute(iteration_count, Bin, Attributes) ->
    parse_iteration_count(Bin, Attributes);
parse_attribute(proof, Bin, Attributes) ->
    parse_proof(Bin, Attributes);
parse_attribute(server_error_or_verifier, Bin, Attributes) ->
    parse_server_error_or_verifier(Bin, Attributes).

parse_gs2_cbind_flag(<<"p=", _/binary>>, _) ->
    {error, 'channel-binding-not-supported'};
parse_gs2_cbind_flag(<<"n">>, Attributes) ->
    {ok, Attributes#{gs2_cbind_flag => not_supported}};
parse_gs2_cbind_flag(<<"y">>, Attributes) ->
    {ok, Attributes#{gs2_cbind_flag => supported_but_not_used}};
parse_gs2_cbind_flag(_, _) ->
    {error, 'other-error'}.

parse_authzid(<<>>, Attributes) ->
    {ok, Attributes};
parse_authzid(<<"a=", AuthzID0/binary>>, Attributes)
  when AuthzID0 =/= <<>> ->
    case replace_escape_sequence(AuthzID0) of
        {ok, AuthzID} ->
            {ok, Attributes#{authzid => AuthzID}};
        {error, Reason} ->
            {error, Reason}
    end;
parse_authzid(_, _) ->
    {error, 'other-error'}.

parse_username(<<"n=", Username0/binary>>, Attributes)
  when Username0 =/= <<>> ->
    case replace_escape_sequence(Username0) of
        {ok, Username} ->
            {ok, Attributes#{username => Username}};
        {error, Reason} ->
            {error, Reason}
    end;
parse_username(_, _) ->
    {error, 'other-error'}.

parse_nonce(<<"r=", Nonce/binary>>, Attributes)
  when Nonce =/= <<>> ->
    {ok, Attributes#{nonce => Nonce}};
parse_nonce(_, _) ->
    {error, 'other-error'}.

%% channel-binding: base64 encoding of cbind-input
%% cbind-input: gs2-header [cbind-data]
%%
%% TODO: The server MUST always validate the client's "c=" field. 
%% The server does this by constructing the value of the "c=" attribute
%% and then checking that it matches the client's c= attribute value.
parse_channel_binding(<<"c=", ChannelBinding0/binary>>, Attributes) ->
    try base64:decode(ChannelBinding0) of
        <<"p=", _/binary>> ->
            {error, 'server-does-support-channel-binding'};
        Decoded ->
            case parse_attributes(Decoded, [gs2_cbind_flag, authzid, cbind_data]) of
                {ok, Attributes0} ->
                    {ok, maps:merge(Attributes, Attributes0)};
                {error, Reason} ->
                    {error, Reason}
            end
    catch
        _Class:_Reason ->
            {error, 'invalid-encoding'}
    end;
parse_channel_binding(_, _) ->
    {error, 'other-error'}.

parse_cbind_data(<<>>, Attributes) ->
    {ok, Attributes};
parse_cbind_data(Bin, Attributes) ->
    {ok, Attributes#{cbind_data => Bin}}.

parse_salt(<<"s=", Salt0/binary>>, Attributes)
  when Salt0 =/= <<>> ->
    try base64:decode(Salt0) of
        Salt ->
            {ok, Attributes#{salt => Salt}}
    catch
        _Class:_Reason ->
            {error, 'invalid-encoding'}
    end;
parse_salt(_, _) ->
    {error, 'other-error'}.

parse_iteration_count(<<"i=", IterationCount0/binary>>, Attributes) ->
    try binary_to_integer(IterationCount0) of
        IterationCount when IterationCount > 0 ->
            {ok, Attributes#{iteration_count => IterationCount}};
        _ ->
            {error, 'other-error'}
    catch
        _Class:_Reason ->
            {error, 'other-error'}
    end;
parse_iteration_count(_, _) ->
    {error, 'other-error'}.

parse_proof(<<"p=", Proof0/binary>>, Attributes)
  when Proof0 =/= <<>> ->
    try base64:decode(Proof0) of
        Proof ->
            {ok, Attributes#{proof => Proof}}
    catch
        _Class:_Reason ->
            {error, 'invalid-encoding'}
    end;
parse_proof(_, _) ->
    {error, 'other-error'}.

parse_server_error_or_verifier(<<"v=", Verifier0/binary>>, Attributes)
  when Verifier0 =/= <<>> ->
    try base64:decode(Verifier0) of
        Verifier ->
            {ok, Attributes#{verifier => Verifier}}
    catch
        _Class:_Reason ->
            {error, 'invalid-encoding'}
    end;
parse_server_error_or_verifier(<<"e=", Error/binary>>, Attributes)
  when Error =/= <<>> ->
    {ok, Attributes#{error => Error}};
parse_server_error_or_verifier(_, _) ->
    {error, 'other-error'}.

skip_extensions([], _) ->
    {error, 'other-error'};
skip_extensions([Chunk | More], Parser) ->
    case Parser(Chunk, #{}) of
        {ok, Attribute} ->
            {ok, Attribute, More};
        {error, _Reason} ->
            skip_extensions(More, Parser)
    end.

replace_escape_sequence(SaslName) ->
    Chunks = binary:split(SaslName, <<"=">>, [global]),
    case replace_escape_sequence(Chunks, []) of
        {error, Reason} ->
            {error, Reason};
        NChunks ->
            {ok, iolist_to_binary(NChunks)}
    end.

replace_escape_sequence([], Acc) ->
    lists:reverse(Acc);
replace_escape_sequence([<<"2C">> | More], Acc) ->
    replace_escape_sequence(More, [<<",">> | Acc]);
replace_escape_sequence([<<"3D">> | More], Acc) ->
    replace_escape_sequence(More, [<<"=">> | Acc]);
replace_escape_sequence([Other | More], Acc) ->
    replace_escape_sequence(More, [Other | Acc]).

%% client-first-message-bare = [reserved-mext ","] userame "," nonce ["," extensions]
client_first_message_bare(Username) ->
    iolist_to_binary(["n=", Username, ",r=", nonce()]).

client_final_message_without_proof(Nonce) ->
    iolist_to_binary(["c=", base64:encode(gs2_header()), ",r=", Nonce]).

client_final_message(Nonce, Proof) ->
    iolist_to_binary([client_final_message_without_proof(Nonce), ",p=", base64:encode(Proof)]).

server_first_message(Nonce, Salt, IterationCount) ->
    iolist_to_binary(["r=", Nonce, ",s=", base64:encode(Salt), ",i=", integer_to_list(IterationCount)]).

server_final_message(verifier, ServerSignature) ->
    iolist_to_binary(["v=", base64:encode(ServerSignature)]);
server_final_message(error, Error) ->
    iolist_to_binary(["e=", Error]).

gen_salt() ->
    <<X:128/big-unsigned-integer>> = crypto:strong_rand_bytes(16),
    iolist_to_binary(io_lib:format("~32.16.0b", [X])).

%% 0x21-2B, 0x2D-7E
nonce() ->
    list_to_binary([rand_uniform(33, 127) || _ <- lists:seq(1,15)]).

salted_password(Alg, Password, Salt, IterationCount) ->
    pbkdf2(Alg, Password, Salt, IterationCount).

client_key(Alg, SaltedPassword) ->
    hmac(Alg, SaltedPassword, <<"Client Key">>).

server_key(Alg, SaltedPassword) ->
    hmac(Alg, SaltedPassword, <<"Server Key">>).

stored_key(Alg, ClientKey) ->
    crypto:hash(Alg, ClientKey).

%% gs2-header = gs2-cbind-flag "," [authzid] ","
gs2_header() ->
    gs2_cbind_flag("n") ++ ",,".

%% n: client doesn't support channel binding
%% y: client does support channel binding but thinks the server does not
%% p: client requires channel binding
gs2_cbind_flag({"p", ChannelBindingName}) ->
    lists:concat(["p=", ChannelBindingName]);
gs2_cbind_flag("n") ->
    "n";
gs2_cbind_flag("y") ->
    "y".

hmac(Algorithm, Key, Data) ->
    crypto:mac(hmac, Algorithm, Key, Data).

rand_uniform(Lo, Hi) ->
    case rand:uniform(Hi - Lo) + Lo of
        44 -> 45;
        N -> N
    end.

pbkdf2(Alg, Password, Salt, IterationCount) ->
    crypto:pbkdf2_hmac(Alg, Password, Salt, IterationCount, keylen(Alg)).

keylen(sha) -> 20;
keylen(sha224) -> 28;
keylen(sha256) -> 32;
keylen(sha284) -> 48;
keylen(sha512) -> 64.

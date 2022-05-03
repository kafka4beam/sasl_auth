-module(sasl_auth_tests).


-include_lib("eunit/include/eunit.hrl").


nif_lib_should_load_test() ->
    sasl_auth:kinit(<<"something">>, <<"something">>).

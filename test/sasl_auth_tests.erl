-module(sasl_auth_tests).


-include_lib("eunit/include/eunit.hrl").


wrap_setup_cleanup(TestCases) ->
    [
     {setup,
     fun setup_nif/0,
     fun cleanup_nif/1,
     TestCases}
    ].

nif_lib_should_load_t() ->
    [?_assert(hej =/= sasl_auth:kinit(<<"something">>, <<"something">>))].

nif_lib_should_load_test_() -> wrap_setup_cleanup(nif_lib_should_load_t()).

setup_nif() ->
    ok.

cleanup_nif(_) ->
    true = code:delete(sasl_auth),
    true = code:soft_purge(sasl_auth).

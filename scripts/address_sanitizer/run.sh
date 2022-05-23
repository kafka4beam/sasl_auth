#!/usr/bin/env bash

echo "============================================"
echo "Note that the \"test/address_sanitizer_setup.sh\" has to run"
echo "successfully at least once before this script will work."
echo "============================================"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd "$SCRIPT_DIR/../../otp"

export ERL_TOP=`pwd`
export PATH=$ERL_TOP/bin:$PATH

cd "$SCRIPT_DIR/../.."
export MEMSAN_DEBUG=1

cp "$ERL_TOP/lib/erl_interface/obj/`$ERL_TOP/erts/autoconf/config.guess`/libei.a" c_src/

rebar3 as addr_san_test,test compile

echo "============================================"
echo "Running the eunit test with address sanitizer"
echo "============================================"

export ASAN_LOG_DIR=`pwd`/asan_logs

(rm -rf "$ASAN_LOG_DIR" || true)

mkdir "$ASAN_LOG_DIR"

# ASAN_OPTIONS=intercept_tls_get_addr=0 is a workaround for a bug in address sanitizer that we hit
# https://github.com/google/sanitizers/issues/1322
# https://github.com/neovim/neovim/pull/17213

mkdir test_results

# ASAN_OPTIONS=intercept_tls_get_addr=0
cerl -asan -noshell -pa _build/addr_san_test+test/lib/sasl_auth/test -pa _build/addr_san_test+test/lib/sasl_auth/ebin -eval 'ct:run_test([{dir,["_build/addr_san_test+test/lib/sasl_auth/ebin","_build/addr_san_test+test/lib/sasl_auth/test"]},{logdir,"./test_results"}]),erlang:halt()' 

echo "============================================"
echo "The address sanitizer log (located in \"$ASAN_LOG_DIR\") will now be printed:"
echo "============================================"

cd "$ASAN_LOG_DIR" && ls . | xargs -n1 cat 


rebar3 as addr_san_test,test clean

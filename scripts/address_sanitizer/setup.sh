#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd "$SCRIPT_DIR/../.."

if [ ! -d otp ]
then
    git clone https://github.com/erlang/otp.git

    cd otp

    export ERL_TOP=`pwd`
    export PATH=$ERL_TOP/bin:$PATH

    git checkout 26.2.5
    if [ $? != 0 ]
    then
        echo "Could not check out desired Erlang version"
        exit 1
    fi

    ./configure

    make -j 4

    cd erts/emulator

    make asan
fi

cd "$SCRIPT_DIR/../../otp"

export ERL_TOP=`pwd`
export PATH=$ERL_TOP/bin:$PATH

cd "$SCRIPT_DIR/../.."

rebar3 clean

cp "$ERL_TOP/lib/erl_interface/obj/`$ERL_TOP/erts/autoconf/config.guess`/libei.a" c_src/

export MEMSAN_DEBUG=1

rebar3 as addr_san_test,test compile

echo "======================================================================================="
echo "Things are now set up to run tests with address sanitizer (if nothing has gone wrong)"
echo
echo "The following have been compiled with address sanitizer :"
echo
echo "1. An Erlang VM (located in otp)"
echo "2. The NIF library"
echo
echo "You can now run the eunit test with address sanitizer  with the command:"
echo "./scripts/address_sanitizer/run_tests.sh"
echo
echo "To run or compile the jq NIF library without address sanitizer  again, you"
echo "have to first run \"rebar3 clean\""
echo "======================================================================================="

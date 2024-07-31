#!/usr/bin/env bash

source ./scripts/setup_and_run_rebar3_ct_in_docker/setup.sh

echo RUN TESTS

if [ "${1:-}" = asan ]
then
    ./scripts/address_sanitizer/setup.sh
    ./scripts/address_sanitizer/run.sh
else
    . /opt/kerl/26.2.5/activate
    rebar3 clean
    rebar3 ct
fi

TEST_RESULT=$?

echo CLEANUP

rebar3 clean
rebar3 as test clean

# Remove _build so we don't get permission problems

rm -rf _build
exit $TEST_RESULT

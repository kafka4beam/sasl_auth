#!/usr/bin/env bash

docker images

docker run --rm \
-v $(pwd):/sasl_auth \
-w /sasl_auth \
sasl_auth_ubuntu_docker:latest \
scripts/setup_and_run_rebar3_ct_in_docker/setup_and_run.sh

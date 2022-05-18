#!/usr/bin/env bash

docker build -f scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile -t sasl_auth_ubuntu_docker:latest .

docker run --rm -it \
-v $(pwd):/sasl_auth \
-w /sasl_auth \
sasl_auth_ubuntu_docker:latest \
scripts/setup_and_run_rebar3_ct_in_docker/setup_and_run.sh

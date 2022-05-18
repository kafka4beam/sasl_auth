#!/usr/bin/env bash

export DOCKER_BUILDKIT=1

docker build -f scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile -t sasl_auth_ubuntu_docker:latest .

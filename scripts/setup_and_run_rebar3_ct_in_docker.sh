#!/usr/bin/env bash

# Separated into tow steps to make github action workflow work

./scripts/setup_and_run_rebar3_ct_in_docker/build_docker_image.sh

./scripts/setup_and_run_rebar3_ct_in_docker/run_in_docker.sh

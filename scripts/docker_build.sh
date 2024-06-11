#!/bin/sh
docker build -f scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile.centos7 -t sasl_auth:latest .

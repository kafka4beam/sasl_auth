#!/usr/bin/env bash

if [ -z ${SASL_AUTH_DOCKER_FILE+x} ]
then
    SASL_AUTH_DOCKER_FILE=scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile.ubuntu22.04
fi

SASL_AUTH_DOCKER_IMAGE="sasl_auth_`basename $SASL_AUTH_DOCKER_FILE`:latest"
SASL_AUTH_DOCKER_IMAGE=`echo $SASL_AUTH_DOCKER_IMAGE | tr '[:upper:]' '[:lower:]'`

docker run --rm \
--hostname example.com \
-v $(pwd):/sasl_auth \
-w /sasl_auth \
$SASL_AUTH_DOCKER_IMAGE \
scripts/setup_and_run_rebar3_ct_in_docker/setup_and_run.sh "$@"

#!/usr/bin/env bash

export DOCKER_BUILDKIT=1


if [ -z ${SASL_AUTH_DOCKER_FILE+x} ]
then
    SASL_AUTH_DOCKER_FILE=scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile.ubuntu22.04
fi

SASL_AUTH_DOCKER_IMAGE="sasl_auth_`basename $SASL_AUTH_DOCKER_FILE`:latest"
SASL_AUTH_DOCKER_IMAGE=`echo $SASL_AUTH_DOCKER_IMAGE | tr '[:upper:]' '[:lower:]'`

docker build -f $SASL_AUTH_DOCKER_FILE -t $SASL_AUTH_DOCKER_IMAGE .

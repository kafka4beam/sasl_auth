#!/bin/bash

## This is a cliet/server interaction test
## It makes use of Erlang message pass to send and receive messages

set -euo pipefail

KRB5_IMAGE='sasl_auth_dockerfile.ubuntu22.04'
#ERLANGE_IMAGE='ghcr.io/emqx/emqx-builder/5.3-9:1.15.7-26.2.5-3-ubuntu22.04'
ERLANGE_IMAGE="$KRB5_IMAGE"
NET='example.com'
REALM='EXAMPLE.COM'
KRB5_SERER="kerberos.$NET"
CLI="cli.$NET"
SRV="srv.$NET"
SERVICE='kafka'
CLI_PRINC="user@${REALM}"
SRV_PRINC="$SERVICE/${SRV}@${REALM}"

cleanup() {
    docker rm -f "$CLI" >/dev/null 2>&1 || true
    docker rm -f "$SRV" >/dev/null 2>&1 || true
    docker rm -f "$KRB5_SERER" >/dev/null 2>&1 || true
    docker network rm "$NET" || true
}
cleanup

erlc scripts/int_test.erl

docker network create "$NET"

docker run -d \
    --net "$NET" \
    -e KRB5_REALM="$REALM" \
    -e KRB5_KDC="$KRB5_SERER" \
    -e KRB5_PASS=public \
    --hostname $KRB5_SERER \
    --name $KRB5_SERER \
    -v $(pwd):/sasl_auth \
    -w /sasl_auth \
    $KRB5_IMAGE \
    bash -c 'scripts/setup_and_run_rebar3_ct_in_docker/setup.sh && sleep 10000'

docker run -d \
    --net $NET \
    --hostname $CLI \
    --name $CLI \
    -v $(pwd):/sasl_auth \
    -w /sasl_auth \
    -e REALM=${REALM} \
    -e SRV=${SRV} \
    -e SERVICE=${SERVICE} \
    -e CLI_PRINC="${CLI_PRINC}" \
    -e SRV_PRINC="${SRV_PRINC}" \
    $ERLANGE_IMAGE bash -c 'sleep 100000'

docker run -d \
    --net $NET \
    --hostname $SRV \
    --name $SRV \
    -v $(pwd):/sasl_auth \
    -w /sasl_auth \
    -e REALM=${REALM} \
    -e SERVICE=${SERVICE} \
    -e SRV_PRINC="${SRV_PRINC}" \
    $ERLANGE_IMAGE bash -c 'sleep 100000'

echo 'wait for krb5 server to be ready'
sleep 5

docker cp $KRB5_SERER:/etc/krb5.conf ./krb5.conf
docker cp krb5.conf $CLI:/etc/krb5.conf
docker cp krb5.conf $SRV:/etc/krb5.conf

# It seems the server must have keytab file in /etc/krb5.keytab
docker exec $SRV cp /sasl_auth/priv/kafka.keytab /etc/krb5.keytab

## run client and server in two different shells:
# docker exec -it cli.example.com erl -sname cli -setcookie abcd -pa _build/default/lib/sasl_auth/ebin -eval 'int_test:start().'
# docker exec -it srv.example.com erl -sname cli -setcookie abcd -pa _build/default/lib/sasl_auth/ebin -eval 'int_test:start().'

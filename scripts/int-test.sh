#!/bin/bash

## This is a cliet/server interaction test
## It makes use of Erlang message pass to send and receive messages

set -euo pipefail

KRB5_IMAGE='sasl_auth_dockerfile.ubuntu22.04'
ERLANGE_IMAGE='ghcr.io/emqx/emqx-builder/5.3-9:1.15.7-26.2.5-3-ubuntu22.04'
#ERLANGE_IMAGE="$KRB5_IMAGE"
NET='example.com'
REALM='EXAMPLE.COM'
KRB5_SERER="kerberos.$NET"
CLI="cli.$NET"
SRV="srv.$NET"
SERVICE='kafka'
CLI_NAME="client/$CLI"
CLI_PRINC="${CLI_NAME}@${REALM}"
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
    -p 88:88 \
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
    -e CLI_NAME="${CLI_NAME}" \
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
    -e KRB5_KTNAME=FILE:/sasl_auth/srv.keytab \
    $ERLANGE_IMAGE bash -c 'sleep 100000'

echo 'wait for krb5 server to be ready'
sleep 3

docker cp $KRB5_SERER:/etc/krb5.conf ./krb5.conf
docker cp krb5.conf $CLI:/etc/krb5.conf
docker cp krb5.conf $SRV:/etc/krb5.conf

rm -f cli.keytab srv.keytab
docker exec $KRB5_SERER kadmin.local -q "addprinc -randkey $SRV_PRINC"
docker exec $KRB5_SERER kadmin.local -q "addprinc -randkey $CLI_PRINC"
docker exec $KRB5_SERER kadmin.local -q "ktadd -k srv.keytab -norandkey $SRV_PRINC"
docker exec $KRB5_SERER kadmin.local -q "ktadd -k cli.keytab -norandkey $CLI_PRINC"

sudo chmod 644 *.keytab

## This seems to be a must for now.
#docker cp srv.keytab $SRV:/etc/krb5.keytab

## run client and server in two different shells:
echo 'docker exec -it cli.example.com erl -sname cli -setcookie abcd -pa _build/default/lib/sasl_auth/ebin -eval "int_test:start(100)."'
echo 'docker exec -it srv.example.com erl -sname srv -setcookie abcd -pa _build/default/lib/sasl_auth/ebin -eval "int_test:start(100)."'

#!/usr/bin/env bash

echo ADDING TO HOSTS FILE

echo '127.0.0.1       example.com' >> /etc/hosts
echo '127.0.0.1       kerberos.example.com' >> /etc/hosts

cp ./scripts/setup_and_run_rebar3_ct_in_docker/krb5.conf /etc/krb5.conf

echo CREATE REALM DB

kdb5_util -P password -r EXAMPLE.COM create -s

echo START KDC

krb5kdc -n &
/usr/bin/kadmind -nofork &

echo ADD USER PRINCIPAL

kadmin.local addprinc -pw password user@EXAMPLE.COM

echo 'ADD KAFKA PRINCIPAL (NO ACTUAL KAFKA INSTALLATION)'

kadmin.local addprinc -randkey kafka/localhost
kadmin.local ktadd  kafka/localhost


echo CREATE KEYTAB FOR USER

export SASL_AUTH_TEST_HOST=example.com
export SASL_AUTH_TEST_KEY_TAB=/sasl_auth/priv/user.keytab
export SASL_AUTH_TEST_PRINCIPAL=user

printf "%b" "addent -password -p $SASL_AUTH_TEST_PRINCIPAL -k 1 -e aes256-cts-hmac-sha1-96\npassword\nwrite_kt $SASL_AUTH_TEST_PRINCIPAL.keytab" | ktutil

echo MOVE KEYTAB

mv  $SASL_AUTH_TEST_KEY_TAB $SASL_AUTH_TEST_KEY_TAB.orgcopy

ls priv

mv $SASL_AUTH_TEST_PRINCIPAL.keytab $SASL_AUTH_TEST_KEY_TAB

echo RUN TESTS

if [ $1 = asan ]
then
    ./scripts/address_sanitizer/setup.sh
    ./scripts/address_sanitizer/run.sh
else
    . /opt/kerl/24.2.1/activate
    rebar3 clean
    rebar3 ct
fi

TEST_RESULT=$?

echo CLEANUP

rm $SASL_AUTH_TEST_KEY_TAB
mv $SASL_AUTH_TEST_KEY_TAB.orgcopy $SASL_AUTH_TEST_KEY_TAB

rebar3 clean
rebar3 as test clean

# Remove _build so we don't get permission problems

rm -rf _build

exit $TEST_RESULT

#!/usr/bin/env bash

echo ADDING TO HOSTS FILE

echo '127.0.0.1       example.com' >> /etc/hosts
echo '127.0.0.1       kerberos.example.com' >> /etc/hosts

cp ./scripts/setup_and_run_rebar3_ct_in_docker/krb5.conf /etc/krb5.conf

echo CREATE REALM DB

kdb5_util -P password -r EXAMPLE.COM create -s

echo START KDC

touch /var/lib/krb5kdc/kadm5.acl

krb5kdc -n &

kadmind -nofork &

echo ADD USER PRINCIPAL

kadmin.local addprinc -pw password user@EXAMPLE.COM

echo 'ADD KAFKA PRINCIPAL (NO ACTUAL KAFKA INSTALLATION)'

echo CREATE KEYTAB FOR USER

export SASL_AUTH_TEST_HOST=example.com
export SASL_AUTH_TEST_KEY_TAB=/sasl_auth/priv/user.keytab
export SASL_AUTH_TEST_PRINCIPAL=user

rm kafka.keytab
export SASL_AUTH_KAFKA_KEY_TAB=/sasl_auth/priv/kafka.keytab
export SASL_AUTH_KAFKA_PRINCIPAL=kafka/example.com

kadmin.local -w password -q "add_principal -randkey kafka/example.com@EXAMPLE.COM"
kadmin.local -w password -q "ktadd  -k kafka.keytab -norandkey kafka/example.com@EXAMPLE.COM "

## Unfortunately simply piping to ktutil did not work on Alpine OS so we use
## the expect script instead (inspired from code found here
## https://localcoder.org/script-kerberos-ktutil-to-make-keytabs).
##
## printf "%b" "addent -password -p $SASL_AUTH_TEST_PRINCIPAL -k 1 -e aes256-cts-hmac-sha1-96\npassword\nwrite_kt $SASL_AUTH_TEST_PRINCIPAL.keytab" | ktutil

expect << EOF
    set timeout 10
    spawn /usr/bin/ktutil
    expect {
       "ktutil: " { send "addent -password -p $SASL_AUTH_TEST_PRINCIPAL -k 1 -e aes256-cts-hmac-sha1-96\r" }
       timeout { puts "Timeout waiting for ktutil prompt."; exit 1; }
    }
    expect {
       -re "Password for \\\\S+: " { send "password\r" }
       timeout { puts "Timeout waiting for password prompt."; exit 1; }
    }
    expect {
       "ktutil: " { send "wkt $SASL_AUTH_TEST_PRINCIPAL.keytab\r" }
    }
    expect {
       "ktutil: " { send "q\r" }
    }
EOF

echo MOVE KEYTAB

mv  $SASL_AUTH_TEST_KEY_TAB $SASL_AUTH_TEST_KEY_TAB.orgcopy > /dev/null 2>&1
mv $SASL_AUTH_TEST_PRINCIPAL.keytab $SASL_AUTH_TEST_KEY_TAB

mv  $SASL_AUTH_KAFKA_KEY_TAB $SASL_AUTH_KAFKA_KEY_TAB.orgcopy > /dev/null 2>&1
mv  kafka.keytab $SASL_AUTH_KAFKA_KEY_TAB
cp  $SASL_AUTH_KAFKA_KEY_TAB /etc/krb5.keytab
echo RUN TESTS

if [ $1 = asan ]
then
    ./scripts/address_sanitizer/setup.sh
    ./scripts/address_sanitizer/run.sh
else
    . /opt/kerl/26.2.5/activate
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

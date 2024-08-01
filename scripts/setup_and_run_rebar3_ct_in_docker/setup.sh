#!/usr/bin/env bash

echo ADDING TO HOSTS FILE

echo '127.0.0.1       example.com' >> /etc/hosts
echo '127.0.0.1       kerberos.example.com' >> /etc/hosts

cp ./scripts/setup_and_run_rebar3_ct_in_docker/krb5.conf /etc/krb5.conf

echo CREATE REALM DB

export SASL_AUTH_TEST_REALM='EXAMPLE.COM'

kdb5_util -P password -r "$SASL_AUTH_TEST_REALM" create -s

echo START KDC

touch /var/lib/krb5kdc/kadm5.acl

krb5kdc -n &

kadmind -nofork &

echo ADD USER PRINCIPAL

kadmin.local addprinc -pw password "user"

echo 'ADD KAFKA PRINCIPAL (NO ACTUAL KAFKA INSTALLATION)'

echo CREATE KEYTAB FOR USER

export SASL_AUTH_TEST_KEY_TAB=/sasl_auth/priv/user.keytab
export SASL_AUTH_TEST_PRINCIPAL=user
export SASL_AUTH_TEST_SERVER_HOST='srv.example.com'

export SASL_AUTH_KAFKA_KEY_TAB=/sasl_auth/priv/kafka.keytab
export SASL_AUTH_KAFKA_PRINCIPAL="kafka/${SASL_AUTH_TEST_SERVER_HOST}@${SASL_AUTH_TEST_REALM}"

kadmin.local -w password -q "addprinc -randkey kafka/${SASL_AUTH_TEST_SERVER_HOST}@${SASL_AUTH_TEST_REALM}"
kadmin.local -w password -q "ktadd -k kafka.keytab -norandkey kafka/${SASL_AUTH_TEST_SERVER_HOST}@${SASL_AUTH_TEST_REALM}"

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

mv user.keytab $SASL_AUTH_TEST_KEY_TAB
mv kafka.keytab $SASL_AUTH_KAFKA_KEY_TAB
chmod 644 /sasl_auth/priv/*.keytab
cp $SASL_AUTH_KAFKA_KEY_TAB /etc/krb5.keytab

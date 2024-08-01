#!/usr/bin/env bash

echo '127.0.0.1       kerberos.example.com' >> /etc/hosts

cp ./scripts/setup_and_run_rebar3_ct_in_docker/krb5.conf /etc/krb5.conf

export SASL_AUTH_TEST_REALM='EXAMPLE.COM'

kdb5_util -P password -r "$SASL_AUTH_TEST_REALM" create -s

touch /var/lib/krb5kdc/kadm5.acl

krb5kdc -n &

kadmind -nofork &

export SASL_AUTH_TEST_KEY_TAB=/sasl_auth/priv/user.keytab
# user in default realm
#export SASL_AUTH_TEST_PRINCIPAL=user
# user with explict realm
export SASL_AUTH_TEST_PRINCIPAL="user/foo.bar@${SASL_AUTH_TEST_REALM}"
export SASL_AUTH_TEST_SERVER_HOST='srv.example.com'

export SASL_AUTH_KAFKA_KEY_TAB=/sasl_auth/priv/kafka.keytab
export SASL_AUTH_KAFKA_PRINCIPAL="kafka/${SASL_AUTH_TEST_SERVER_HOST}@${SASL_AUTH_TEST_REALM}"

kadmin.local -q "addprinc -randkey ${SASL_AUTH_TEST_PRINCIPAL}"
kadmin.local -q "ktadd -k user.keytab -norandkey $SASL_AUTH_TEST_PRINCIPAL"
kadmin.local -q "addprinc -randkey kafka/${SASL_AUTH_TEST_SERVER_HOST}@${SASL_AUTH_TEST_REALM}"
kadmin.local -q "ktadd -k kafka.keytab -norandkey kafka/${SASL_AUTH_TEST_SERVER_HOST}@${SASL_AUTH_TEST_REALM}"

mv user.keytab $SASL_AUTH_TEST_KEY_TAB
mv kafka.keytab $SASL_AUTH_KAFKA_KEY_TAB
chmod 644 /sasl_auth/priv/*.keytab
cp $SASL_AUTH_KAFKA_KEY_TAB /etc/krb5.keytab

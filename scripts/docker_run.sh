#!/bin/sh
docker run --rm -it \
--hostname example.com \
--name sasl_auth \
-e SASL_AUTH_TEST_HOST=$SASL_AUTH_TEST_HOST \
-e SASL_AUTH_TEST_KEY_TAB=$SASL_AUTH_TEST_KEY_TAB \
-e SASL_AUTH_TEST_PRINCIPAL=$SASL_AUTH_TEST_PRINCIPAL \
-e SASL_AUTH_SERVICE_KEY_TAB=$SASL_AUTH_SERVICE_KEY_TAB \
-e SASL_AUTH_SERVICE_PRINCIPAL=$SASL_AUTH_SERVICE_PRINCIPAL \
-v $(pwd):/sasl_auth \
-v /etc/krb5.conf:/etc/krb5.conf.d/krb5.conf \
-w /sasl_auth \
sasl_auth:latest \
/bin/bash

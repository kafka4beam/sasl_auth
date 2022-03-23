sasl_auth
=====

sasl_auth is a simple wrapper for cyrus sasl library (https://cyrusimap.org/docs/cyrus-sasl/2.1.23/programming.php)
It helps to implement SASL GSSAPI auth mechanism support in your erlang application.

Dependencies
-----

libsasl2, libsasl2-dev, libkrb5, libkrb5-dev should be installed to build and use sasl_auth

Build
-----

    $ rebar3 compile

Use
-----

sasl_auth used in https://github.com/ElMaxo/brod_gssapi - GSSAPI auth backend for brod (https://github.com/klarna/brod) Apache Kafka client library for Erlang/Elixir. See usage details here

Test in a docker container
----
- Make sure to delete `c_src\sasl_auth.o` and `priv\sasl_auth.so` file if exists
- Generate keytab file for your user using `kinit` command e.g. `kinit -kt PATH_TO_KEY_TAB USER` and copy it to /priv dir
- Run `sh scripts/docker_build.sh`
- Have a krb5.conf copied to your local /etc folder with correct kerberos config. This file is mapped to docker container
- Set environment variables:
  - SASL_AUTH_TEST_HOST - Host name
  - SASL_AUTH_TEST_KEY_TAB - full Path to keytab file.
  - SASL_AUTH_TEST_PRINCIPAL - user name
- Run `sh scripts/docker_run.sh`
- Run `rebar3 ct`

Use
-----

sasl_auth used in https://github.com/ElMaxo/brod_gssapi - GSSAPI auth backend for brod (https://github.com/klarna/brod) Apache Kafka client library for Erlang/Elixir. See usage details here

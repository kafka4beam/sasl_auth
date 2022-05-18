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

Run `./scripts/setup_and_run_rebar3_ct_in_docker.sh`

Use
-----

sasl_auth used in https://github.com/ElMaxo/brod_gssapi - GSSAPI auth backend for brod (https://github.com/klarna/brod) Apache Kafka client library for Erlang/Elixir. See usage details here

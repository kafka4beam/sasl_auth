sasl_auth
=====

sasl_auth is a simple wrapper for [cyrus sasl library](https://www.cyrusimap.org/sasl/).
It helps to implement SASL GSSAPI auth mechanism support in your Erlang
application.

Dependencies
-----

libsasl2, libsasl2-dev, libkrb5, libkrb5-dev should be installed to build and use sasl_auth

Build
-----

    $ rebar3 compile

Use
-----

sasl_auth used in https://github.com/ElMaxo/brod_gssapi - GSSAPI auth backend for brod (https://github.com/klarna/brod) Apache Kafka client library for Erlang/Elixir. See usage details here

# SASL Authentication Library for Erlang/Elixir

This library provides two SASL implementations
- The `sasl_auth` module implements a simple wrapper for [cyrus sasl library](https://www.cyrusimap.org/sasl/).
  It helps to implement SASL GSSAPI auth mechanism support in your Erlang application.
- The `sasl_auth_scram` module implements SASL SCRAM authentication functions.

## Dependencies

### Ubuntu

On Ubuntu the following packages should be installed to build and use
`sasl_auth`: libkrb5, libkrb5-dev, libsasl2, libsasl2-dev,
libsasl2-modules-gssapi-mit.

See the dockerfiles in `scripts/setup_and_run_rebar3_ct_in_docker` for
information about which packages are needed for other Linux distributions.

### Redhat based distributions

#### Redhat 7 based distribution or compatabile

The following packages are required on Redhat 7 based or compatible distributions :
cyrus-sasl, cyrus-sasl-devel, cyrus-sasl-gssapi, krb5-devel, and krb5-libs.

Use either yum or dnf (depending on redhat base version) to install cyrus-sasl, cyrus-sasl-gssapi, and krb5-libs.

```shell
yum install cyrus-sasl cyrus-sasl-devel cyrus-sasl-gssapi krb5-devel krb5-libs
```

#### Redhat 8 based distributions or compatabile

The following packages are required on Redhat 8 based or compatible distributions :
cyrus-sasl-libs, cyrus-sasl-devel, cyrus-sasl-gssapi, krb5-devel, and krb5-libs.


```shell
dnf install cyrus-sasl-libs cyrus-sasl-devel cyrus-sasl-gssapi krb5-devel krb5-libs
```

#### Mac OS

Install `cyrus-sasl` via homebrew, this includes the gssapi module, as well MIT krb5 as a dependency :

```shell
brew install cyrus-sasl
```

## Build

```
$ rebar3 compile
```


## Test

You can execute the tests with the following command (if you have
[Docker](https://www.docker.com/) installed):

```
./scripts/setup_and_run_rebar3_ct_in_docker.sh
```

By default, the script above runs the test in a docker container that is
created from a docker image that is described in the file
`scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile.ubuntu22.04`. You can
change the dockerfile by specifying the environment
variable `SASL_AUTH_DOCKER_FILE`. The following command will run
the tests in a Centos7 docker image:

```
SASL_AUTH_DOCKER_FILE=scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile.centos7 ./scripts/setup_and_run_rebar3_ct_in_docker.sh
```

You can execute the following command to run the tests in a docker container
with Erlang/OTP and the NIF library compiled with [address
sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer) (finds
memory errors and leaks):

```
./scripts/setup_and_run_rebar3_ct_in_docker.sh asan
```


It is a little bit more complicated to run the tests without Docker and the
exact steps may depend on the operating system you are using. The following
steps outlines what needs to be done:

1. Install necessary packages
   * The dockerfile `scripts/setup_and_run_rebar3_ct_in_docker/Dockerfile.ubuntu22.04`
     contains information about which packages need to be installed in Ubuntu.
2. Configure a Kerberos server and create a keytab for a user
   * This can be done by following the steps in
     `scripts/setup_and_run_rebar3_ct_in_docker/setup_and_run.sh` until the
     command `echo RUN TESTS`.
3. Export and set the following environment variables to appropriate values:

   ```
   export SASL_AUTH_TEST_HOST=example.com  # Host that Kerberos is running on
   export SASL_AUTH_TEST_PRINCIPAL=user  # A user name
   export SASL_AUTH_TEST_KEY_TAB=user.keytab  # Keytab for user
   ```
5. Run the tests:

   `rebar3 ct`


## References

### `sasl_auth`

- [brod_gssapi](https://github.com/kafka4beam/brod_gssapi) A GSSAPI authentication backend for [the Apache Kafka client library for Erlang/Elixir brod](https://github.com/kafka4beam/brod). See usage details in the [README file for brod_gssapi](https://github.com/kafka4beam/brod_gssapi).
- Opensource MQTT broker [EMQX](https://github.com/emqx/emqx)

### `sasl_auth_scram`

- Opensource MQTT broker [EMQX](https://github.com/emqx/emqx)
- There is also a similar but independent client-side-only implementation for reference: [kpro_scram](https://github.com/kafka4beam/kafka_protocol/blob/master/src/kpro_scram.erl).

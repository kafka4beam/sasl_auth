#define _DEFAULT_SOURCE 200112L
#include <erl_nif.h>
#include <krb5.h>
#include <sasl/sasl.h>
#include <string.h>

// MIT is broken
#ifdef KRB5_KRB5_H_INCLUDED
#define KRB5KDC_ERR_KEY_EXPIRED KRB5KDC_ERR_KEY_EXP
#endif

#ifdef UNUSED
#elif defined(__GNUC__)
#define UNUSED(x) UNUSED_##x __attribute__((unused))
#elif defined(__LCLINT__)
#define UNUSED(x) /*@unused@*/ x
#else
#define UNUSED(x) x
#endif

static ERL_NIF_TERM ATOM_OK;
static ERL_NIF_TERM ATOM_ERROR;
static ERL_NIF_TERM ATOM_OOM;
static ERL_NIF_TERM ATOM_UNKNOWN;
static ERL_NIF_TERM ATOM_NOT_CONTROLLING_PROCESS;

#define OK_TUPLE(env, ret) enif_make_tuple2(env, ATOM_OK, ret)
#define SASL_STEP_TUPLE(env, code, out, outlen)                                                    \
    OK_TUPLE(env, enif_make_tuple2(env, enif_make_int(env, code), str_to_bin(env, out, outlen)))
#define ERROR_TUPLE(env, ret) enif_make_tuple2(env, ATOM_ERROR, ret)
#define SASL_ERROR_TUPLE(env, state, code)                                                         \
    ERROR_TUPLE(env, enif_make_tuple2(env, enif_make_int(env, code), sasl_error(env, state)));

#define KT_NAME_LEN 1024
#define DEFAULT_CCNAME "MEMORY:krb5cc_sasl_auth"


typedef struct {
    sasl_conn_t* conn;
    sasl_callback_t callbacks[16];
    unsigned char* principal;
    unsigned char* service;
    unsigned char* host;
    unsigned char* user;
    ErlNifPid controlling_process;
    ErlNifMutex* controller_lock;
    int mech_set;
} sasl_state_t;

// SASL connection nif resource
static ErlNifResourceType* sasl_client_connection_nif_resource_type = NULL;
static ErlNifResourceType* sasl_server_connection_nif_resource_type = NULL;

static void destroy_resource(ErlNifEnv* UNUSED(env), sasl_state_t* state)
{
    if (state != NULL) {
        if (state->conn != NULL) {
            if (state->controller_lock != NULL) {
                enif_mutex_lock(state->controller_lock);
            }

            sasl_dispose(&state->conn);

            if (state->controller_lock != NULL) {
                enif_mutex_unlock(state->controller_lock);
            }
        }
        if (state->controller_lock != NULL) {
            enif_mutex_destroy(state->controller_lock);
        }

        if (state->principal != NULL) {
            enif_free(state->principal);
        }

        if (state->user != NULL) {
            enif_free(state->user);
        }

        if (state->service != NULL) {
            enif_free(state->service);
        }
        if (state->host != NULL) {
            enif_free(state->host);
        }
    }
}

static void* sasl_mutex_alloc(void) { return enif_mutex_create("sasl_auth.callback"); }

static int sasl_mutex_lock(ErlNifMutex* mutex)
{
    int ret;

    if (mutex == NULL) {
        ret = 1;
    } else {
        enif_mutex_lock(mutex);
        ret = 0;
    }

    return ret;
}

static int sasl_mutex_unlock(ErlNifMutex* mutex)
{
    int ret;
    if (mutex == NULL) {
        ret = 1;
    } else {
        enif_mutex_unlock(mutex);
        ret = 0;
    }

    return ret;
}

static void sasl_mutex_free(ErlNifMutex* mutex)
{
    if (mutex != NULL) {
        enif_mutex_destroy(mutex);
    }

    return;
}

static ErlNifResourceType* init_resource_type(ErlNifEnv* env, const char* name)
{
    return enif_open_resource_type(env, NULL, name, (ErlNifResourceDtor*)destroy_resource,
        ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
}

static int load(ErlNifEnv* env, void** UNUSED(priv), ERL_NIF_TERM UNUSED(info))
{
    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_ERROR = enif_make_atom(env, "error");
    ATOM_OOM = enif_make_atom(env, "out_of_memory");
    ATOM_UNKNOWN = enif_make_atom(env, "unknown");
    ATOM_NOT_CONTROLLING_PROCESS = enif_make_atom(env, "not_controlling_process");

    sasl_set_mutex((sasl_mutex_alloc_t*)&sasl_mutex_alloc, (sasl_mutex_lock_t*)&sasl_mutex_lock,
        (sasl_mutex_unlock_t*)&sasl_mutex_unlock, (sasl_mutex_free_t*)&sasl_mutex_free);

    sasl_client_connection_nif_resource_type = init_resource_type(env, "sasl_auth_cli_state");
    int cli_result = sasl_client_init(NULL);
    sasl_server_connection_nif_resource_type = init_resource_type(env, "sasl_auth_srv_state");
    int srv_result = sasl_server_init(NULL, "sasl_auth");
    setenv("KRB5CCNAME", DEFAULT_CCNAME, 1);
    return !sasl_client_connection_nif_resource_type && !(cli_result == SASL_OK)
        && !sasl_server_connection_nif_resource_type && !(srv_result == SASL_OK);
}

static int upgrade(
    ErlNifEnv* UNUSED(env), void** UNUSED(priv), void** UNUSED(old_priv), ERL_NIF_TERM UNUSED(info))
{
    return 0;
}

static void unload(ErlNifEnv* UNUSED(env), void* UNUSED(priv))
{
    sasl_done();
    return;
}

static unsigned char* copy_bin(ErlNifBinary bin)
{
    unsigned char* new;
    unsigned char* old_data = bin.data;
    new = enif_alloc(bin.size);
    if (new == NULL) {
        return NULL;
    } else {
        memcpy(new, old_data, bin.size);
        return new;
    }
}

static ERL_NIF_TERM str_to_bin(ErlNifEnv* env, const char* string, unsigned long len)
{

    ERL_NIF_TERM ret;

    unsigned char* ptr = enif_make_new_binary(env, len, &ret);

    (void)memcpy(ptr, string, len);

    return ret;
}

static ERL_NIF_TERM sasl_error(ErlNifEnv* env, sasl_state_t* state)
{

    const char* string = sasl_errdetail(state->conn);
    return str_to_bin(env, string, strlen(string));
}

static int sasl_cyrus_cb_getsimple(void* context, int id, const char** result, unsigned int* len)
{

    switch (id) {
    case SASL_CB_USER:
    case SASL_CB_AUTHNAME:
        *result = context;
        break;
    default:
        *result = NULL;
    }

    if (len) {
        *len = *result ? (unsigned int)strlen(*result) : 0;
    }

    return *result ? SASL_OK : SASL_FAIL;
}

static int sasl_auth_process_check(ErlNifEnv* env, sasl_state_t* state)
{
    int is_controlling_process;
    ErlNifPid current_process;

    enif_self(env, &current_process);

    enif_mutex_lock(state->controller_lock);

    is_controlling_process = enif_is_identical(
        enif_make_pid(env, &current_process), enif_make_pid(env, &state->controlling_process));

    enif_mutex_unlock(state->controller_lock);

    return is_controlling_process;
}

static ERL_NIF_TERM sasl_cli_new(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    ErlNifBinary service, serverfqdn, principal, user;
    ERL_NIF_TERM return_state;

    sasl_state_t* state = NULL;

    if ((!enif_inspect_binary(env, argv[0], &service))
        || (!enif_inspect_binary(env, argv[1], &serverfqdn))
        || (!enif_inspect_binary(env, argv[2], &principal))
        || (!enif_inspect_binary(env, argv[3], &user))) {
        return enif_make_badarg(env);
    }

    state = enif_alloc_resource(sasl_client_connection_nif_resource_type, sizeof(sasl_state_t));

    if (!state) {
        enif_release_resource(state);
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    state->mech_set = 0;

    enif_self(env, &state->controlling_process);

    state->controller_lock = enif_mutex_create("sasl_auth_client.controller_lock");

    state->principal = copy_bin(principal);
    if (state->principal == NULL) {
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    state->user = copy_bin(user);
    if (state->user == NULL) {
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    state->service = copy_bin(service);
    if (state->service == NULL) {
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    state->host = copy_bin(serverfqdn);

    if (state->host == NULL) {
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    sasl_callback_t callbacks[16]
        = { { SASL_CB_USER, (void*)sasl_cyrus_cb_getsimple, state->user },
              { SASL_CB_AUTHNAME, (void*)sasl_cyrus_cb_getsimple, state->user },
              { SASL_CB_LIST_END } };

    memcpy(state->callbacks, callbacks, sizeof(callbacks));

    enif_mutex_lock(state->controller_lock);

    int result = sasl_client_new((const char*)state->service, (const char*)state->host, NULL, NULL,
        state->callbacks, 0, &state->conn);

    enif_mutex_unlock(state->controller_lock);
    switch (result) {
    case SASL_OK:
        return_state = enif_make_resource(env, state);
        enif_release_resource(state);
        return OK_TUPLE(env, return_state);
    default:
        enif_free(state->principal);
        state->principal = NULL;
        enif_free(state->user);
        state->user = NULL;
        enif_free(state->service);
        state->service = NULL;
        enif_free(state->host);
        state->host = NULL;
        enif_mutex_destroy(state->controller_lock);
        state->controller_lock = NULL;
        enif_release_resource(state);
        return ERROR_TUPLE(env, enif_make_int(env, result));
    }
}

static ERL_NIF_TERM sasl_list_mech(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{

    const char* avail_mechs;
    sasl_state_t* state;
    int res;

    if ((!enif_get_resource(
            env, argv[0], sasl_client_connection_nif_resource_type, (void**)&state))) {
        return enif_make_badarg(env);
    } else if (!sasl_auth_process_check(env, state)) {
        return enif_raise_exception(env, ATOM_NOT_CONTROLLING_PROCESS);
    }

    enif_mutex_lock(state->controller_lock);

    res = sasl_listmech(state->conn, NULL, NULL, " ", NULL, &avail_mechs, NULL, NULL);

    enif_mutex_unlock(state->controller_lock);

    if (SASL_OK == res) {
        return OK_TUPLE(env, str_to_bin(env, avail_mechs, strlen(avail_mechs)));
    } else {
        return ERROR_TUPLE(
            env, enif_make_tuple2(env, enif_make_int(env, res), sasl_error(env, state)));
    }
}

static ERL_NIF_TERM sasl_cli_start(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    sasl_state_t* state;
    int result;
    const char *out, *mech;
    unsigned int outlen;

    if ((!enif_get_resource(
            env, argv[0], sasl_client_connection_nif_resource_type, (void**)&state))) {
        return enif_make_badarg(env);
    } else if (!sasl_auth_process_check(env, state)) {
        return enif_raise_exception(env, ATOM_NOT_CONTROLLING_PROCESS);
    }

    enif_mutex_lock(state->controller_lock);

    result = sasl_client_start(state->conn, "GSSAPI", NULL, &out, &outlen, &mech);

    enif_mutex_unlock(state->controller_lock);

    ERL_NIF_TERM ret;
    if (SASL_CONTINUE == result) {
        state->mech_set = 1;

        ret = SASL_STEP_TUPLE(env, result, out, (unsigned long)outlen);
    } else {
        ret = SASL_ERROR_TUPLE(env, state, result);
    }

    return ret;
}

static ERL_NIF_TERM sasl_cli_step(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    ErlNifBinary challenge;
    sasl_state_t* state;

    if ((!enif_get_resource(env, argv[0], sasl_client_connection_nif_resource_type, (void**)&state))
        || (!enif_inspect_binary(env, argv[1], &challenge))) {
        return enif_make_badarg(env);
    } else if (!sasl_auth_process_check(env, state)) {
        return enif_raise_exception(env, ATOM_NOT_CONTROLLING_PROCESS);
    }

    int result = 0;
    const char* out;
    unsigned int outlen;
    unsigned char* challenge_in = NULL;
    ERL_NIF_TERM ret;

    sasl_interact_t* interact = NULL;

    if (state->mech_set && state->conn) {
        challenge_in = copy_bin(challenge);
        if (challenge_in == NULL) {
            return ERROR_TUPLE(env, ATOM_OOM);
        }
        enif_mutex_lock(state->controller_lock);

        result
            = sasl_client_step(state->conn, challenge.size > 0 ? (const char*)challenge_in : NULL,
                (unsigned int)challenge.size, &interact, &out, &outlen);

        enif_mutex_unlock(state->controller_lock);

        switch (result) {
        case SASL_OK:
            ret = SASL_STEP_TUPLE(env, result, out, (unsigned long)outlen);
            break;
        case SASL_CONTINUE:
        case SASL_INTERACT:
            ret = SASL_STEP_TUPLE(env, result, out, (unsigned long)outlen);
            break;
        default:
            ret = SASL_ERROR_TUPLE(env, state, result);
        }
    } else {

        ret = ERROR_TUPLE(
            env, enif_make_tuple2(env, enif_make_int(env, -4), str_to_bin(env, "No MECH set", 12)));
    }
    enif_free(challenge_in);
    return ret;
}

static ERL_NIF_TERM sasl_cli_done(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    sasl_state_t* state;
    ERL_NIF_TERM ret;

    if ((!enif_get_resource(
            env, argv[0], sasl_client_connection_nif_resource_type, (void**)&state))) {
        return enif_make_badarg(env);
    } else if (!sasl_auth_process_check(env, state)) {
        return enif_raise_exception(env, ATOM_NOT_CONTROLLING_PROCESS);
    }

    enif_mutex_lock(state->controller_lock);
    sasl_dispose(&state->conn);
    enif_mutex_unlock(state->controller_lock);
    state->conn = NULL;

    enif_mutex_destroy(state->controller_lock);
    state->controller_lock = NULL;

    enif_free(state->principal);
    state->principal = NULL;

    enif_free(state->host);
    state->host = NULL;

    enif_free(state->service);
    state->service = NULL;

    ret = ATOM_OK;
    return ret;
}

// server begin
static ERL_NIF_TERM sasl_srv_new(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    ErlNifBinary service, serverfqdn, principal;
    ERL_NIF_TERM return_state;

    if ((!enif_inspect_binary(env, argv[0], &service))
        || (!enif_inspect_binary(env, argv[1], &serverfqdn))
        || (!enif_inspect_binary(env, argv[2], &principal))) {
        return enif_make_badarg(env);
    }

    sasl_state_t* state
        = enif_alloc_resource(sasl_server_connection_nif_resource_type, sizeof(sasl_state_t));

    if (!state) {
        enif_release_resource(state);
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    state->mech_set = 0;
    if(serverfqdn.size == 1) {
        // null-terminate string, 1 means empty.
        // this means server hostname will be resolved from gethostname() later.
        state->host = NULL;
    }
    else{
        state->host = copy_bin(serverfqdn);
        if (state->host == NULL) {
            return ERROR_TUPLE(env, ATOM_OOM);
        }
    }

    enif_self(env, &state->controlling_process);

    state->controller_lock = enif_mutex_create("sasl_auth_server.controller_lock");
    state->principal = copy_bin(principal);
    if (state->principal == NULL) {
        return ERROR_TUPLE(env, ATOM_OOM);
    }
    // server never need this
    state->user = NULL;

    state->service = copy_bin(service);
    if (state->service == NULL) {
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    sasl_callback_t callbacks[16]
        = { { SASL_CB_USER, (void*)sasl_cyrus_cb_getsimple, state->principal },
              { SASL_CB_AUTHNAME, (void*)sasl_cyrus_cb_getsimple, state->principal },
              { SASL_CB_LIST_END } };

    memcpy(state->callbacks, callbacks, sizeof(callbacks));

    int result = sasl_server_new(
        (const char*)state->service, (const char*)state->host, NULL, NULL, NULL, state->callbacks, 0, &state->conn);

    switch (result) {
    case SASL_OK:
        return_state = enif_make_resource(env, state);
        enif_release_resource(state);
        return OK_TUPLE(env, return_state);
    default:
        enif_free(state->principal);
        state->principal = NULL;
        enif_free(state->service);
        state->service = NULL;
        enif_mutex_destroy(state->controller_lock);
        state->controller_lock = NULL;
        enif_release_resource(state);
        return ERROR_TUPLE(env, enif_make_int(env, result));
    }
}

static ERL_NIF_TERM sasl_srv_start(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    sasl_state_t* state;
    ErlNifBinary clientin;
    const char* serverout;
    unsigned int serveroutlen = 0;

    if ((!enif_get_resource(env, argv[0], sasl_server_connection_nif_resource_type, (void**)&state))
        || (!enif_inspect_binary(env, argv[1], &clientin))) {
        return enif_make_badarg(env);
    } else if (!sasl_auth_process_check(env, state)) {
        return enif_raise_exception(env, ATOM_NOT_CONTROLLING_PROCESS);
    }
    enif_mutex_lock(state->controller_lock);

    int result = sasl_server_start(state->conn, "GSSAPI",
        clientin.size > 0 ? (const char*)clientin.data : NULL, (unsigned int)clientin.size,
        &serverout, &serveroutlen);

    enif_mutex_unlock(state->controller_lock);

    ERL_NIF_TERM ret;
    if (SASL_CONTINUE == result) {
        state->mech_set = 1;
        ret = SASL_STEP_TUPLE(env, result, serverout, (unsigned long)serveroutlen);
    } else {
        ret = SASL_ERROR_TUPLE(env, state, result);
    }
    return ret;
}

static ERL_NIF_TERM sasl_srv_step(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    ErlNifBinary challenge;
    sasl_state_t* state;
    unsigned char* challenge_in = NULL;

    if ((!enif_get_resource(env, argv[0], sasl_server_connection_nif_resource_type, (void**)&state))
        || (!enif_inspect_binary(env, argv[1], &challenge))) {
        return enif_make_badarg(env);
    } else if (!sasl_auth_process_check(env, state)) {
        return enif_raise_exception(env, ATOM_NOT_CONTROLLING_PROCESS);
    }

    int result = 0;
    const char* out;
    unsigned int outlen;
    ERL_NIF_TERM ret;

    if (state->mech_set && state->conn) {
        challenge_in = copy_bin(challenge);
        if (challenge_in == NULL) {
            return ERROR_TUPLE(env, ATOM_OOM);
        }
        enif_mutex_lock(state->controller_lock);
        result
            = sasl_server_step(state->conn, challenge.size > 0 ? (const char*)challenge_in : NULL,
                (unsigned int)challenge.size, &out, &outlen);

        enif_mutex_unlock(state->controller_lock);

        switch (result) {
        case SASL_OK:
            ret = SASL_STEP_TUPLE(env, result, out, (unsigned long)outlen);
            break;
        case SASL_CONTINUE:
        case SASL_INTERACT:
            ret = SASL_STEP_TUPLE(env, result, out, (unsigned long)outlen);
            break;
        default:
            ret = SASL_ERROR_TUPLE(env, state, result);
        }
    } else {
        ret = ERROR_TUPLE(
            env, enif_make_tuple2(env, enif_make_int(env, -4), str_to_bin(env, "No MECH set", 12)));
    }
    return ret;
}

static ERL_NIF_TERM sasl_srv_done(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    sasl_state_t* state;
    ERL_NIF_TERM ret;

    if ((!enif_get_resource(
            env, argv[0], sasl_server_connection_nif_resource_type, (void**)&state))) {
        return enif_make_badarg(env);
    } else if (!sasl_auth_process_check(env, state)) {
        return enif_raise_exception(env, ATOM_NOT_CONTROLLING_PROCESS);
    }

    enif_mutex_lock(state->controller_lock);
    sasl_dispose(&state->conn);
    enif_mutex_unlock(state->controller_lock);
    state->conn = NULL;

    enif_mutex_destroy(state->controller_lock);
    state->controller_lock = NULL;

    enif_free(state->principal);
    state->principal = NULL;

    enif_free(state->service);
    state->service = NULL;

    ret = ATOM_OK;
    return ret;
}
// server end

static ERL_NIF_TERM sasl_krb5_kt_default_name(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM UNUSED(argv[]))
{
    krb5_context context;
    krb5_error_code ret;
    char name[KT_NAME_LEN];
    ret = krb5_init_context(&context);
    if (ret) {
        return enif_make_badarg(env);
    }

    ret = krb5_kt_default_name(context, name, sizeof(name) - 1);
    if (ret) {
        krb5_free_context(context);
        return enif_make_badarg(env);
    }

    ErlNifBinary retbin;
    if (enif_alloc_binary(strlen(name), &retbin))
    {
        memcpy(retbin.data, name, retbin.size);
        ERL_NIF_TERM result = enif_make_binary(env, &retbin);
        krb5_free_context(context);
        return result;
    }
    else
    {
        return enif_raise_exception(env, ATOM_OOM);
    }
}

static void enif_free_non_null(void* ptr) {
    if (ptr != NULL) {
        enif_free(ptr);
    }
}

static ERL_NIF_TERM sasl_kinit(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{

    ErlNifBinary keytab_bin;
    ErlNifBinary principal_bin;
    ErlNifBinary ccname_bin;
    unsigned char* principal_char = NULL;
    unsigned char* keytab_char = NULL;
    unsigned char* ccname_char = NULL;
    ERL_NIF_TERM ret;
    ERL_NIF_TERM error_tag;
    ERL_NIF_TERM error_code;
    ERL_NIF_TERM error_message;
    ERL_NIF_TERM error_tup;

    krb5_error_code error = 0;
    krb5_principal principal = NULL;
    krb5_context context = NULL;
    krb5_creds creds = { .magic = 0 };
    krb5_keytab kt_handle = NULL;
    krb5_ccache ccache = NULL;
    krb5_get_init_creds_opt* options = NULL;

    const char* krb_error_msg;
    const char* tag;
    int handle_alive = 0;
    int cache_alive = 0;

    if ( !enif_inspect_binary(env, argv[0], &keytab_bin) ) {
        return enif_make_badarg(env);
    }
    if ( !enif_inspect_binary(env, argv[1], &principal_bin) ) {
        return enif_make_badarg(env);
    }
    if ( !enif_inspect_binary(env, argv[2], &ccname_bin) ) {
        return enif_make_badarg(env);
    }

    keytab_char = copy_bin(keytab_bin);
    if (keytab_char == NULL) {
        ret = ERROR_TUPLE(env, ATOM_OOM);
        goto kinit_free_chars;
    }

    principal_char = copy_bin(principal_bin);
    if (principal_char == NULL) {
        ret = ERROR_TUPLE(env, ATOM_OOM);
        goto kinit_free_chars;
    }

    ccname_char = copy_bin(ccname_bin);
    if (ccname_char == NULL) {
        ret = ERROR_TUPLE(env, ATOM_OOM);
        goto kinit_free_chars;
    }

    if ((error = krb5_init_context(&context)) != 0) {
        tag = "krb5_parse_context";
        goto kinit_finish;
    }

    if ((error = krb5_parse_name(context, (const char*)principal_char, &principal)) != 0) {
        tag = "krb5_parse_name";
        goto kinit_finish;
    }

    if ((error = krb5_kt_resolve(context, (const char*)keytab_char, &kt_handle)) != 0) {
        tag = "krb5_kt_resolve";
        goto kinit_finish;
    }

    handle_alive = 1;

    /* NOTWORKING: (error = krb5_cc_resolve(context, (const char*)ccname_char, &ccache))
     *
     * krb5 doc says krb5_cc_default is essentially krb5_cc_resolve with default ccname, but it does not work.
     * So we set environment variable KRB5CCNAME and call krb5_cc_default instead */
    if (ccname_char[0] != 0) {
        setenv("KRB5CCNAME", (const char*)ccname_char, 1);
    }
    if ((error = krb5_cc_default(context, &ccache)) != 0) {
        tag = "krb5_cc_default";
        goto kinit_finish;
    }

    cache_alive = 1;

    if ((error = krb5_get_init_creds_opt_alloc(context, &options)) != 0) {
        tag = "krb5_get_init_creds_opt_alloc";
        goto kinit_finish;
    }

/* It's not clear why this call fails on mac. For the time being initially keytab init must
 * be done on the command line */
#if (!defined __APPLE__ || !defined __MACH__)
    if ((error = krb5_get_init_creds_opt_set_out_ccache(context, options, ccache)) != 0) {
        tag = "krb5_get_init_creds_opt_set_out_ccache";
        goto kinit_finish;
    }
#endif


    if ((error = krb5_get_init_creds_keytab(context, &creds, principal, kt_handle, 0, NULL, options)) != 0) {
        tag = "krb5_get_init_creds_keytab";
        goto kinit_finish;
    }

kinit_finish:

    if (error == 0) {
        ret = ATOM_OK;
    } else {
        krb_error_msg = krb5_get_error_message(context, error);
        error_tag = str_to_bin(env, (const char*)tag, strlen((const char*)tag));
        error_code = enif_make_int(env, error);
        error_message = str_to_bin(env, krb_error_msg, strlen(krb_error_msg));
        error_tup = enif_make_tuple3(env, error_tag, error_code, error_message);
        krb5_free_error_message(context, krb_error_msg);
        ret = ERROR_TUPLE(env, error_tup);
    }

    if (1 == cache_alive) {
        krb5_cc_close(context, ccache);
    }

    if (1 == handle_alive) {
        krb5_kt_close(context, kt_handle);
    }

    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, principal);
    if (options != NULL) {
        krb5_get_init_creds_opt_free(context, options);
    }
    krb5_free_context(context);

kinit_free_chars:

    enif_free_non_null(principal_char);
    enif_free_non_null(keytab_char);
    enif_free_non_null(ccname_char);
    return ret;
}

static ErlNifFunc nif_funcs[]
    = { { "sasl_client_new", 4, sasl_cli_new, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_listmech", 1, sasl_list_mech, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_client_start", 1, sasl_cli_start, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_client_step", 2, sasl_cli_step, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_client_done", 1, sasl_cli_done, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_kinit", 3, sasl_kinit, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_server_new", 3, sasl_srv_new, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_server_start", 2, sasl_srv_start, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_server_step", 2, sasl_srv_step, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_server_done", 1, sasl_srv_done, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_krb5_kt_default_name", 0, sasl_krb5_kt_default_name, ERL_NIF_DIRTY_JOB_CPU_BOUND }
       };

ERL_NIF_INIT(sasl_auth, nif_funcs, &load, NULL, &upgrade, &unload)

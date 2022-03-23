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

ERL_NIF_TERM ATOM_OK;
ERL_NIF_TERM ATOM_ERROR;
ERL_NIF_TERM ATOM_OOM;
ERL_NIF_TERM ATOM_UNKNOWN;

#define OK_TUPLE(env, ret) enif_make_tuple2(env, ATOM_OK, ret)
#define SASL_STEP_TUPLE(env, code, out, outlen)                                                    \
    OK_TUPLE(env, enif_make_tuple2(env, enif_make_int(env, code), str_to_bin(env, out, outlen)))
#define ERROR_TUPLE(env, ret) enif_make_tuple2(env, ATOM_ERROR, ret)
#define SASL_ERROR_TUPLE(env, state, code)                                                         \
    ERROR_TUPLE(env, enif_make_tuple2(env, enif_make_int(env, code), sasl_error(env, state)));

typedef struct {
    sasl_conn_t* conn;
    sasl_callback_t callbacks[16];
    int mech_set;
} sasl_state_t;

// SASL connection state
static ErlNifResourceType* sasl_resource = NULL;

static void destroy_resource(ErlNifEnv* UNUSED(env), sasl_state_t* res)
{
    if (res != NULL) {
        sasl_dispose(&res->conn);
    }
}

static ErlNifResourceType* init_resource_type(ErlNifEnv* env)
{
    return enif_open_resource_type(env, NULL, "sasl_auth_state",
        (ErlNifResourceDtor*)destroy_resource, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
}

static int load(ErlNifEnv* env, void** UNUSED(priv), ERL_NIF_TERM UNUSED(info))
{
    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_ERROR = enif_make_atom(env, "error");
    ATOM_OOM = enif_make_atom(env, "out_of_memory");
    ATOM_UNKNOWN = enif_make_atom(env, "unknown");

    sasl_resource = init_resource_type(env);
    int result;
    result = sasl_client_init(NULL);
    return !sasl_resource && !(result == SASL_OK);
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

static ERL_NIF_TERM str_to_bin(ErlNifEnv* env, const char* string, unsigned long len)
{

    ERL_NIF_TERM ret;

    unsigned char* ptr = enif_make_new_binary(env, len, &ret);

    (void)memmove(ptr, string, len);

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

static ERL_NIF_TERM sasl_cli_new(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{
    ErlNifBinary service, host, principal;
    sasl_state_t* state = NULL;

    if ((!enif_inspect_binary(env, argv[0], &service))
        || (!enif_inspect_binary(env, argv[1], &host))
        || (!enif_inspect_binary(env, argv[2], &principal))) {
        return enif_make_badarg(env);
    }

    state = enif_alloc_resource(sasl_resource, sizeof(sasl_state_t));

    if (!state) {
        enif_release_resource(state);
        return ERROR_TUPLE(env, ATOM_OOM);
    }

    state->mech_set = 0;

    sasl_callback_t callbacks[16]
        = { { SASL_CB_USER, (void*)sasl_cyrus_cb_getsimple, principal.data },
              { SASL_CB_AUTHNAME, (void*)sasl_cyrus_cb_getsimple, principal.data },
              { SASL_CB_LIST_END } };

    memcpy(state->callbacks, callbacks, sizeof(callbacks));

    int result;
    result = sasl_client_new((const char*)service.data, (const char*)host.data, NULL, NULL,
        state->callbacks, 0, &state->conn);
    ERL_NIF_TERM term = enif_make_resource(env, state);

    switch (result) {
    case SASL_OK:
        enif_release_resource(state);

        return OK_TUPLE(env, term);
    default:
        enif_release_resource(state);
        return ERROR_TUPLE(env, enif_make_int(env, result));
    }
}

static ERL_NIF_TERM sasl_list_mech(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{

    const char* avail_mechs;
    sasl_state_t* state;
    int res;

    if ((!enif_get_resource(env, argv[0], sasl_resource, (void**)&state))) {
        return enif_make_badarg(env);
    }

    res = sasl_listmech(state->conn, NULL, NULL, " ", NULL, &avail_mechs, NULL, NULL);

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

    if ((!enif_get_resource(env, argv[0], sasl_resource, (void**)&state))) {
        return enif_make_badarg(env);
    }

    result = sasl_client_start(state->conn, "GSSAPI", NULL, &out, &outlen, &mech);

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

    if ((!enif_get_resource(env, argv[0], sasl_resource, (void**)&state))
        || (!enif_inspect_binary(env, argv[1], &challenge))) {
        return enif_make_badarg(env);
    }

    int result = 0;
    const char* out;
    unsigned int outlen;
    ERL_NIF_TERM ret;

    sasl_interact_t* interact = NULL;

    if (state->mech_set) {
        result
            = sasl_client_step(state->conn, challenge.size > 0 ? (const char*)challenge.data : NULL,
                (unsigned int)challenge.size, &interact, &out, &outlen);
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

static ERL_NIF_TERM sasl_kinit(ErlNifEnv* env, int UNUSED(argc), const ERL_NIF_TERM argv[])
{

    ErlNifBinary keytab;
    ErlNifBinary principal_in;
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
    krb5_ccache defcache = NULL;
    krb5_get_init_creds_opt* options = NULL;

    const char* krb_error_msg;
    const char* tag;
    int handle_alive = 0;
    int cache_alive = 0;

    if ((!enif_inspect_binary(env, argv[0], &keytab)
            || !enif_inspect_binary(env, argv[1], &principal_in)))
        return enif_make_badarg(env);

    if ((error = krb5_init_context(&context)) != 0) {
        tag = "krb5_parse_context";
        goto kinit_finish;
    }

    if ((error = krb5_parse_name(context, (const char*)principal_in.data, &principal)) != 0) {
        tag = "krb5_parse_name";
        goto kinit_finish;
    }

    if ((error = krb5_kt_resolve(context, (const char*)keytab.data, &kt_handle)) != 0) {
        tag = "krb5_kt_resolve";
        goto kinit_finish;
    }

    handle_alive = 1;

    if ((error = krb5_cc_default(context, &defcache)) != 0) {
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
    if ((error = krb5_get_init_creds_opt_set_out_ccache(context, options, defcache)) != 0) {
        tag = "krb5_get_init_creds_opt_set_out_ccache";
        goto kinit_finish;
    }
#endif

    if ((error
            = krb5_get_init_creds_keytab(context, &creds, principal, kt_handle, 0, NULL, options))
        != 0) {
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
        krb5_cc_close(context, defcache);
    }

    if (1 == handle_alive) {
        krb5_kt_close(context, kt_handle);
    }

    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, principal);
    krb5_free_context(context);

    return ret;
}

static ErlNifFunc nif_funcs[]
    = { { "sasl_client_new", 3, sasl_cli_new, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_listmech", 1, sasl_list_mech, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_client_start", 1, sasl_cli_start, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_client_step", 2, sasl_cli_step, ERL_NIF_DIRTY_JOB_CPU_BOUND },
          { "sasl_kinit", 2, sasl_kinit, ERL_NIF_DIRTY_JOB_CPU_BOUND } };

ERL_NIF_INIT(sasl_auth, nif_funcs, &load, NULL, &upgrade, &unload)

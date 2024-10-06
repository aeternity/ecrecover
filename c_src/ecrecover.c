// Very specific NIF just for key recovery.
// Partly from https://github.com/mbrix/libsecp256k1

#include "erl_nif.h"
#include "secp256k1_recovery.h"
#include <string.h>


static secp256k1_context *ctx = NULL;

static ERL_NIF_TERM error_result(ErlNifEnv* env, char* error_msg)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_string(env, error_msg, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM ok3_result(ErlNifEnv* env, ERL_NIF_TERM *r1, ERL_NIF_TERM *r2)
{
    return enif_make_tuple3(env, enif_make_atom(env, "ok"), *r1, *r2);
}

static ERL_NIF_TERM ok_result(ErlNifEnv* env, ERL_NIF_TERM *r)
{
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), *r);
}

static ERL_NIF_TERM
sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary messagedigest, privkey, nonce;

  if (!enif_inspect_binary(env, argv[0], &messagedigest)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[1], &privkey)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[2], &nonce)) {
    return enif_make_badarg(env);
  }

  secp256k1_ecdsa_recoverable_signature *signature;
  int recoveryid;

  signature = malloc(sizeof(secp256k1_ecdsa_recoverable_signature));
  memset(signature, 0, sizeof(secp256k1_ecdsa_recoverable_signature));
  if(!signature) {
    return error_result(env, "malloc_error");
  }

  ERL_NIF_TERM to_ret;
  unsigned char* out = enif_make_new_binary(env, 64, &to_ret);

  int result = secp256k1_ecdsa_sign_recoverable(
      ctx,
      signature,
      messagedigest.data,
      privkey.data,
      NULL,
      nonce.data);
  if (!result) {
    free(signature);
    //should out be freed here??
    return error_result(env, "sign_error");
  }
  secp256k1_ecdsa_recoverable_signature_serialize_compact(
      ctx,
      out,
      &recoveryid,
      signature);

  free(signature);

  ERL_NIF_TERM v = enif_make_uint(env, recoveryid && 0xff);

  return ok3_result(env, &to_ret, &v);
}

static ERL_NIF_TERM
recover(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM r;
	ErlNifBinary message, csignature;
	int result;
    int compressed = SECP256K1_EC_UNCOMPRESSED;
	size_t pubkeylen = 65;
	int recid;
    unsigned char* finished_recpubkey_buf;
    secp256k1_ecdsa_recoverable_signature signature;
    secp256k1_pubkey recpubkey;
	
	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &csignature)) {
       return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[2], &recid)) {
		return error_result(env, "Recovery id invalid not integer 0-3");
	}

	if (recid < 0 || recid > 3) {
		return error_result(env, "Recovery id invalid 0-3");
	}

    result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, csignature.data, recid);
	if (!result) {
		return error_result(env, "ecdsa_signature_parse_compact returned 0");
	}

	// Now do ECDSA recovery
	result = secp256k1_ecdsa_recover(ctx, &recpubkey, &signature, message.data);

	if (!result) {
	    return error_result(env, "ecdsa recovery problem");
	}

	// Now serialize recpubkey
	finished_recpubkey_buf = enif_make_new_binary(env, pubkeylen, &r);

	result = secp256k1_ec_pubkey_serialize(ctx, finished_recpubkey_buf,
			&pubkeylen, &recpubkey, compressed);

	if (!result) {
		return error_result(env, "ecdsa pubkey serialize error");
	}

    return ok_result(env, &r);

}


static int
load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return 0;
}

static int
upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info)
{
    return 0;
}

static void
unload(ErlNifEnv* env, void* priv)
{
	secp256k1_context_destroy(ctx);
    return;
}

static ErlNifFunc nif_funcs[] =
  {
   {"recover", 3, recover},
   {"sign", 3, sign}
  };

ERL_NIF_INIT(ecrecover, nif_funcs, &load, NULL, NULL, &unload);

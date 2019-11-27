#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>

#include <openssl/evp.h>
#include "rfc1321/global.h"
#include "rfc1321/md5.h"

static int md5_init(EVP_MD_CTX *ctx)
{
  MD5Init(EVP_MD_CTX_md_data(ctx));
  return 1;
}

static int md5_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
  MD5Update(EVP_MD_CTX_md_data(ctx), data, count);
  return 1;
}

static int md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  MD5Final(md, EVP_MD_CTX_md_data(ctx));
  return 1;
}

static EVP_MD *digest_md5 = NULL;

/* This is a little more advanced than what I show in the OpenSSL
   blog.  It takes a copy of the builtin OpenSSL MD5WithRSAEncryption
   implementation and just changes the init/update/final function
   pointers, thereby keeping the PKEY implementation from OpenSSL.
*/
static void init(void)
{
  EVP_MD *md = EVP_MD_meth_dup(EVP_md5());
  if (md == NULL
      || !EVP_MD_meth_set_result_size(md,16)
      || !EVP_MD_meth_set_input_blocksize(md, 64) /* internal blocksize */
      || !EVP_MD_meth_set_app_datasize(md, sizeof(MD5_CTX))
      || !EVP_MD_meth_set_init(md, md5_init)
      || !EVP_MD_meth_set_update(md, md5_update)
      || !EVP_MD_meth_set_final(md, md5_final)
      || !EVP_MD_meth_set_copy(md, NULL /*md5_digest_copy*/)
      || !EVP_MD_meth_set_cleanup(md, NULL /*md5_digest_cleanup*/)
      ) {
    EVP_MD_meth_free(md);
    md=NULL;
  }

  digest_md5 = md;
};

static int digest_nids[] = { NID_md5, 0 };
static int digests(ENGINE *e, const EVP_MD **digest,
                   const int **nids, int nid)
{
  int ok = 1;
  if (!digest) {
    /* We are returning a list of supported nids */
    *nids = digest_nids;
    return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
  }

  /* We are being asked for a specific digest */
  switch (nid) {
  case NID_md5:
    *digest = digest_md5;
    break;
  default:
    ok = 0;
    *digest = NULL;
    break;
  }
  return ok;
}

static const char *engine_id = "emd5";
static const char *engine_name = "A simple md5 engine for demonstration purposes";
static int bind(ENGINE *e, const char *id)
{
  int ret = 0;

  static int loaded = 0;

  if (id && strcmp(id, engine_id)) {
    fprintf(stderr, "MD5 engine called with the unexpected id %s\n", id);
    fprintf(stderr, "The expected id is %s\n", engine_id);
    goto end;
  }

  if (loaded) {
    fprintf(stderr, "MD5 engine already loaded\n");
    goto end;
  }

  loaded = 1;

  if (!ENGINE_set_id(e, engine_id)) {
    fprintf(stderr, "ENGINE_set_id failed\n");
    goto end;
  }
  if (!ENGINE_set_name(e, engine_name)) {
    printf("ENGINE_set_name failed\n");
    goto end;
  }
  if (!ENGINE_set_digests(e, digests)) {
    printf("ENGINE_set_name failed\n");
    goto end;
  }

  init();

  ret = 1;
 end:
  return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

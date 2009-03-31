/*
 * curl.c
 */

#include "gauche-curl.h"

/*
 * The following function is a dummy one; replace it for
 * your C function definitions.
 */

ScmObj test_curl(void)
{
    return SCM_MAKE_STR("curl is working");
}

/* <curl-base> */
ScmClass *ScmCurlClass;

/* <curl-version-info> */
ScmClass *ScmCurl_VersionInfoClass;

/* <curl-base> cleanup */
static void curl_cleanup(ScmObj obj)
{
  CURL *hnd = SCMCURL_UNBOX(obj);
  curl_easy_cleanup(hnd);
}

struct OutStruct {
  char *filename;
  FILE *stream;
  struct Configurable *config;
  curl_off_t bytes; /* amount written so far */
  curl_off_t init;  /* original size (non-zero when appending) */
};

/* write to port */
size_t write_to_port(void *buffer, size_t sz, size_t nmemb, void *stream)
{
  size_t rc;
  Scm_Write(SCM_MAKE_STR_COPYING(buffer),
	    SCM_OBJ(SCM_CUROUT),
	    SCM_WRITE_DISPLAY);
  rc = sz * nmemb;
  return rc;
}

/* write to error port */
size_t write_to_err_port(void *buffer, size_t sz, size_t nmemb, void *stream)
{
  size_t rc;
  Scm_Write(SCM_MAKE_STR_COPYING(buffer),
	    SCM_OBJ(SCM_CURERR),
	    SCM_WRITE_DISPLAY);
  rc = sz * nmemb;
  return rc;
}

/* static size_t my_fwrite(void *buffer, size_t sz, size_t nmemb, void *stream) */
/* { */
/*   size_t rc; */
/*   struct OutStruct *out=(struct OutStruct *)stream; */
/*   struct Configurable *config = out->config; */

/*   if(!out->stream) { */
/*     /\* open file for writing *\/ */
/*     out->stream=fopen(out->filename, "wb"); */
/*     if(!out->stream) { */
/*       warnf(config, "Failed to create the file %s\n", out->filename); */
/*       /\* */
/*        * Once that libcurl has called back my_fwrite() the returned value */
/*        * is checked against the amount that was intended to be written, if */
/*        * it does not match then it fails with CURLE_WRITE_ERROR. So at this */
/*        * point returning a value different from sz*nmemb indicates failure. */
/*        *\/ */
/*       rc = (0 == (sz * nmemb)) ? 1 : 0; */
/*       return rc; /\* failure *\/ */
/*     } */
/*   } */

/*   rc = fwrite(buffer, sz, nmemb, out->stream); */

/*   if((sz * nmemb) == rc) { */
/*     /\* we added this amount of data to the output *\/ */
/*     out->bytes += (sz * nmemb); */
/*   } */

/*   if(config->nobuffer) */
/*     /\* disable output buffering *\/ */
/*     fflush(out->stream); */

/*   return rc; */
/* }}} */

/* read from port */
size_t read_from_port(void *buffer, size_t sz, size_t nmemb, void *stream)
{
  size_t rc;
  ScmObj curl_input = Scm_Read(SCM_OBJ(SCM_CURIN));
  buffer = curl_input;
  return rc;
}

/* static size_t my_fread(void *buffer, size_t sz, size_t nmemb, void *userp) */
/* { */
/*   ssize_t rc; */
/*   struct InStruct *in=(struct InStruct *)userp; */

/*   rc = read(in->fd, buffer, sz*nmemb); */
/*   if(rc < 0) */
/*     /\* since size_t is unsigned we can't return negative values fine *\/ */
/*     return 0; */
/*   return (size_t)rc; */
/* } */


/*
 * Module initialization function.
 */
extern void Scm_Init_curllib(ScmModule*);

void Scm_Init_curl(void)
{
    ScmModule *mod;

    /* Register this DSO to Gauche */
    SCM_INIT_EXTENSION(curl);

    /* Create the module if it doesn't exist yet. */
    mod = SCM_MODULE(SCM_FIND_MODULE("curl", TRUE));

    ScmCurlClass =
      Scm_MakeForeignPointerClass(mod, "<curl-base>",
				  NULL,
				  curl_cleanup,
    				  SCM_FOREIGN_POINTER_KEEP_IDENTITY|SCM_FOREIGN_POINTER_MAP_NULL);

    ScmCurl_VersionInfoClass =
      Scm_MakeForeignPointerClass(mod, "<curl-version-info>",
				  NULL,
				  NULL,
    				  SCM_FOREIGN_POINTER_KEEP_IDENTITY|SCM_FOREIGN_POINTER_MAP_NULL);

    /* Register stub-generated procedures */
    Scm_Init_curllib(mod);
}

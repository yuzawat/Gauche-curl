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

/* <curl-slist> */
ScmClass *ScmCurl_SListClass;

/* <curl-base> cleanup */
static void curl_cleanup(ScmObj obj)
{
  CURL *hnd = SCMCURL_UNBOX(obj);
  curl_easy_cleanup(hnd);
}

extern ScmObj *OUTPORT = NULL;

/* write to port */
size_t write_to_port(void *buffer, size_t sz, size_t nmemb, void *stream)
{
  ScmObj oport;
  if (OUTPORT) {
    oport = OUTPORT;
  } else {
    oport = SCM_CUROUT;
  }
  size_t rc;
  if (SCM_OPORTP(oport)) {
      Scm_Write(SCM_MAKE_STR_COPYING(buffer),
		SCM_OBJ(oport),
		SCM_WRITE_DISPLAY); 
      rc = sz * nmemb;
  } else {
    rc =  0;
  }
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

extern ScmObj INPORT = NULL;

/* read from port */
size_t read_from_port(void *buffer, size_t sz, size_t nmemb, void *userp)
{
  ScmObj iport;
  if (INPORT) {
    iport = INPORT;
  } else {
    iport = SCM_CURIN;
  }
  size_t rc;
  ScmString *curl_input;
  curl_input = Scm_Read(SCM_OBJ(iport));
  if (SCM_STRINGP(SCM_STRING(curl_input))) {
    buffer = strdup(Scm_GetStringConst(SCM_STRING(curl_input)));
    rc = sz * nmemb;
  } else {
    rc = 0;
  }
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

/* curl_version_info() return version & features as alist */
ScmObj curl_version_info_list(void)
{
  int ver = CURLVERSION_NOW;
  curl_version_info_data* data;
  ScmObj info_list = SCM_NIL, last = SCM_NIL;
  data = curl_version_info(ver);
  SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("version"),
					SCM_MAKE_STR_COPYING(data->version)));
  SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("version_number"),
					SCM_MAKE_INT(data->version_num)));
  SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("host"),
					SCM_MAKE_STR_COPYING(data->host)));
  if (data->ssl_version) {
    SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("ssl_version"),
					  SCM_MAKE_STR_COPYING(data->ssl_version)));
    SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("ssl_version_number"),
					  SCM_MAKE_INT(data->ssl_version_num)));
  }
  if (data->libz_version) {
    SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("libz_version"),
					  SCM_MAKE_STR_COPYING(data->libz_version)));
  }
  if (data->protocols) {
    char pstr[128];
    pstr[0] = '\0';
    const char * const *name;
    for (name=data->protocols; *name; ++name) {
      if (pstr[0] != '\0') strcat(pstr, " ");
      strcat(pstr, *name);
    }
    SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("protocols"),
					  SCM_MAKE_STR_COPYING(pstr)));
  }
  if (data->features) {
    unsigned int i;
    char fstr[128];
    fstr[0] = '\0';
    struct feat {
      const char *name;
      int bitmask;
    };
    static const struct feat feats[] = {
      {"AsynchDNS", CURL_VERSION_ASYNCHDNS},
      {"Debug", CURL_VERSION_DEBUG},
      {"GSS-Negotiate", CURL_VERSION_GSSNEGOTIATE},
      {"IDN", CURL_VERSION_IDN},
      {"IPv6", CURL_VERSION_IPV6},
      {"Largefile", CURL_VERSION_LARGEFILE},
      {"NTLM", CURL_VERSION_NTLM},
      {"SPNEGO", CURL_VERSION_SPNEGO},
      {"SSL",  CURL_VERSION_SSL},
      {"SSPI",  CURL_VERSION_SSPI},
      {"krb4", CURL_VERSION_KERBEROS4},
      {"libz", CURL_VERSION_LIBZ},
      {"CharConv", CURL_VERSION_CONV}
    };
    for(i=0; i<sizeof(feats)/sizeof(feats[0]); i++) {
      if(data->features & feats[i].bitmask) {
	if (fstr[0] != '\0') strcat(fstr, " ");
	strcat(fstr, feats[i].name);
      }
    }
    SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("features"),
					  SCM_MAKE_STR_COPYING(fstr)));
  }
  if (data->age >= CURLVERSION_SECOND) {
    if (data->ares) {
      SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("ares"),
					    SCM_MAKE_STR_COPYING(data->ares)));
      SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("ares_num"),
					    SCM_MAKE_INT(data->ares_num)));
    }
  }
  if (data->age >= CURLVERSION_THIRD) {
    if (data->libidn) {
      SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("libidn"),
					    SCM_MAKE_STR_COPYING(data->libidn)));
    }
  }
  if (data->age >= CURLVERSION_FOURTH) {
    if (data->iconv_ver_num) {
      SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("iconv_ver_num"),
					    SCM_MAKE_INT(data->iconv_ver_num)));
    }
    if (data->libssh_version) {
      SCM_APPEND1(info_list, last, Scm_Cons(SCM_MAKE_STR_COPYING("libssh_version"),
					    SCM_MAKE_STR_COPYING(data->libssh_version)));
    }
  }
  return info_list;
}

struct curl_slist *list_to_curl_slist (ScmObj ls)
{
  struct curl_slist *slist, *last, *next;
  ScmObj str;
  slist = SCM_NEW(struct curl_slist);
  last = SCM_NEW(struct curl_slist);
  SCM_FOR_EACH(str, ls){
    if (!slist->data) {
      slist->data = strdup(Scm_GetStringConst(SCM_STRING(SCM_CAR(str))));
      slist->next = NULL;
    } else {
      next = SCM_NEW(struct curl_slist);
      next->data = strdup(Scm_GetStringConst(SCM_STRING(SCM_CAR(str))));
      next->next = NULL;
      last = slist;
      while (last->next) {
	last = last->next;
      }
      last->next = next;
    }
  }
  return slist;
}

ScmObj curl_slist_to_list (struct curl_slist *slist)
{
  ScmObj head = SCM_NIL, tail = SCM_NIL;
  struct curl_slist *next;
  int i = 0, j = 0;
  next = SCM_NEW(struct curl_slist);
  next = slist;
  while (next->next) {
    i++;
    next = next->next;
  }
  next = slist;
  for (; j <= i; j++) {
    SCM_APPEND1(head, tail, SCM_MAKE_STR_COPYING(next->data));
    next = next->next;
  }
  return head;
}

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

    ScmCurl_SListClass =
      Scm_MakeForeignPointerClass(mod, "<curl-slist>",
				  NULL,
				  NULL,
				  SCM_FOREIGN_POINTER_KEEP_IDENTITY|SCM_FOREIGN_POINTER_MAP_NULL);

    /* Register stub-generated procedures */
    Scm_Init_curllib(mod);
}

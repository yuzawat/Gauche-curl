/*-*- coding: utf-8 -*-*/
/*
 * curl.c
 *
 * Last Updated: "2009/07/05 13:37.35"
 *
 * Copyright (c) 2009  yuzawat <suzdalenator@gmail.com>
 */

#include "gauche-curl.h"

/*
 * The following function is a dummy one; replace it for
 * your C function definitions.
 */

/* <curl-base> */
ScmClass *ScmCurlClass;

/* <curl-multi-base> */
ScmClass *ScmCurlMClass;

/* <curl-share-base> */
ScmClass *ScmCurlSHClass;

/* <curl-slist> */
ScmClass *ScmCurl_SListClass;

/* <curl-base> cleanup */
static void curl_cleanup(ScmObj obj)
{
  CURL *hnd = SCMCURL_UNBOX(obj);
  curl_easy_cleanup(hnd);
}

/* <curl-multi-base> cleanup */
static void curlm_cleanup(ScmObj obj)
{
  CURLM *mhnd = SCMCURLM_UNBOX(obj);
  curl_multi_cleanup(mhnd);
}

/* <curl-share-base> cleanup */
static void curlsh_cleanup(ScmObj obj)
{
  CURLSH *shhnd = SCMCURLSH_UNBOX(obj);
  curl_share_cleanup(shhnd);
}


/* write to file, read from file */
ScmObj curl_open_file(CURL *hnd, int type, const char* fn)
{
  ScmObj *oport;
  FILE* fp;
  int fd, rc;
  mode_t old_mode = umask(S_IRWXO);
   switch (type)
     {
    case CURLOPT_WRITEDATA:
      fd = open(fn, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP);
      fp = fdopen(fd, "w");
      rc = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, fp);
      if (rc != 0) {
	Scm_Error("failed to open file %s\n",fn);
      }
      rc = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, NULL);
      if (rc != 0) {
	Scm_Error("failed to setopt CURLOPT_WRITEFUNCTION\n");
      }
      break;
    case CURLOPT_WRITEHEADER:
      fd = open(fn, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP);
      fp = fdopen(fd, "w");
      rc = curl_easy_setopt(hnd, CURLOPT_WRITEHEADER, fp);
      if (rc != 0) {
	Scm_Error("failed to open file %s\n",fn);
      }
      rc = curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, NULL);
      if (rc != 0) {
	Scm_Error("failed to setopt CURLOPT_HEADERFUNCTION\n");
      }
      break;
    case CURLOPT_STDERR:
      fd = open(fn, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP);
      fp = fdopen(fd, "w");
      rc = curl_easy_setopt(hnd, CURLOPT_STDERR, fp);
      if (rc != 0) {
	Scm_Error("failed to open file %s\n",fn);
      }
      break;
    case CURLOPT_READDATA:
      fd = open(fn, O_RDONLY);
      fp = fdopen(fd, "r");
      rc = curl_easy_setopt(hnd, CURLOPT_READDATA, fp);
      if (rc != 0) {
	Scm_Error("failed to open file %s\n",fn);
      }
      rc = curl_easy_setopt(hnd, CURLOPT_READFUNCTION, NULL);
      if (rc != 0) {
	Scm_Error("failed to setopt CURLOPT_READFUNCTION\n");
      }
      break;
    default:
      Scm_Error("Invalid option type\n");
      return NULL;
      break;
    }
   umask(old_mode);
   return SCM_UNDEFINED;
}

/* write to port, read from port */
ScmObj curl_open_port(CURL* hnd, int type, ScmObj *scm_port)
{
  ScmObj *port = scm_port;
  int rc, input_size;
  FILE* fp;
  switch (type)
    {
    case CURLOPT_WRITEDATA:
      rc = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, port);
      if (rc != 0) {
	Scm_Error("failed to setopt CURLOPT_WRITEDATA\n");
      }
      rc = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &write_to_port);
      if (rc != 0) {
	Scm_Error("failed to setopt CURLOPT_WRITEFUNCTION\n");
      }
      break;
    case CURLOPT_WRITEHEADER:
      rc = curl_easy_setopt(hnd, CURLOPT_WRITEHEADER, port);
      if (rc != 0) {
	Scm_Error("failed to setopt CURLOPT_WRITEHEADER\n");
      }
      rc = curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, &write_to_port);
      if (rc != 0) {
	Scm_Error("failed to setopt CURLOPT_HEADERFUNCTION\n");
      }
      break;
    case CURLOPT_READDATA:
      /* stdin port*/
      if (SCM_PORT(port) == SCM_PORT(Scm_Stdin())) {
	rc = curl_easy_setopt(hnd, CURLOPT_READDATA, stdin);
	if (rc != 0) {
	  Scm_Error("failed to setopt CURLOPT_READDATA\n");
	}
	rc = curl_easy_setopt(hnd, CURLOPT_READFUNCTION, NULL);
	if (rc != 0) {
	  Scm_Error("failed to setopt CURLOPT_READFUNCTION\n");
	}
	/* And need header, "Transfer-Encoding: chunked" */
      } else {
	/* other port */
	rc = curl_easy_setopt(hnd, CURLOPT_READDATA, port);
	if (rc != 0) {
	  Scm_Error("failed to setopt CURLOPT_READDATA\n");
	}
	if (SCM_PORT_TYPE(port) == SCM_PORT_FILE || 
	    SCM_PORT_TYPE(port) == SCM_PORT_ISTR) {
	  input_size = SCM_INT_VALUE(Scm_PortSeek(SCM_PORT(port), SCM_MAKE_INT(0), SEEK_END));
	  if (input_size) {
	    Scm_PortSeek(SCM_PORT(port), SCM_MAKE_INT(0), SEEK_SET);
	    if (CURL_SIZEOF_CURL_OFF_T > 4) {
	      rc = curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)input_size);
	    } else {
	      rc = curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE, input_size);
	    }
	    if (rc != 0) {
	      Scm_Error("failed to setopt CURLOPT_POSTFIELDSIZE\n");
	    }
	  }
	}
	rc = curl_easy_setopt(hnd, CURLOPT_READFUNCTION, &read_from_port);
	if (rc != 0) {
	  Scm_Error("failed to setopt CURLOPT_READFUNCTION\n");
	}
      }
      break;
    defalut:
      Scm_Error("Invalid option type\n");
      return NULL;
      break;
    }
  return SCM_OBJ(port);
}

/* write to port function */
size_t write_to_port(void *buffer, size_t sz, size_t nmemb, void *scm_port)
{
  ScmObj *oport;
  size_t isize;
  int i, j;
  int times = 0;
  char wbuff[sz];
  char *data = (char*)buffer;
  oport = scm_port;
  isize = sz * nmemb;
  memset(wbuff, 0, sz);

  for (i = 0; i < isize; i += sz) {
    for(j = 0; j <= sz; j++) {
      if (j == sz) {
	Scm_Putz(wbuff, sz, SCM_PORT(oport));
	times++;
	break;
      } else {
	wbuff[j] = *data++;
      }
    }
  }

  if (SCM_PORT_TYPE(SCM_PORT(oport)) == SCM_PORT_FILE)
      Scm_Flush(SCM_PORT(oport));

  if (times == nmemb) {
    return isize;
  } else {
    return 0;
  }
}


/* read from port */
size_t read_from_port(void *buffer, size_t sz, size_t nmemb, void *scm_port)
{
  ScmObj *iport;
  size_t isize;
  int c, nread = 0;
  char *data;

  iport = scm_port;
  isize = sz * nmemb;

  data = buffer;
  while (nread < isize) {
    c = Scm_Getz(data, (int)isize, SCM_PORT(iport));
    data = data + c;
    nread += c;
  }

  if ((size_t)nread >= isize) {
    return isize;
  } else {
    return 0;
  }

}


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
					Scm_Sprintf("%#08x", data->version_num)));
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

  if (SCM_NULLP(ls)) Scm_Error("not allow null list");

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

ScmObj curl_slist_to_list (void *slist)
{
  ScmObj head = SCM_NIL, tail = SCM_NIL;
  if (slist == NULL) {
    return SCM_FALSE;
  } else {
    (struct curl_slist*)slist;
  }
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

ScmObj _curl_easy_getinfo(CURL* hnd, int info)
{
  ScmObj res;
  int rc;
  void *result;
  switch (info)
    {
      /* string */
    case CURLINFO_EFFECTIVE_URL:
    case CURLINFO_CONTENT_TYPE:
    case CURLINFO_PRIVATE:
    case CURLINFO_FTP_ENTRY_PATH:
    case CURLINFO_REDIRECT_URL:
      (const char *)result;
      rc = curl_easy_getinfo(hnd, info, &result);
      if ( rc == 0 ) {
	if (result == NULL) {
	  res = SCM_FALSE;
	} else {
	  res = SCM_MAKE_STR_COPYING(result);
	}
      } else {
	res = SCM_FALSE;
      }
      break;
      /* linked list */
    case CURLINFO_SSL_ENGINES:
    case CURLINFO_COOKIELIST:
      (struct curl_slist *)result;
      rc = curl_easy_getinfo(hnd, info, &result);
      if ( rc == 0) {
	if (result == NULL) {
	  res = SCM_FALSE;
	} else {
	  res = curl_slist_to_list(result);
	}
      } else {
	res = SCM_FALSE;
      }
      break;
      /* long */
    case CURLINFO_RESPONSE_CODE:
    case CURLINFO_HEADER_SIZE:
    case CURLINFO_REQUEST_SIZE:
    case CURLINFO_SSL_VERIFYRESULT:
    case CURLINFO_FILETIME:
    case CURLINFO_REDIRECT_COUNT:
    case CURLINFO_HTTP_CONNECTCODE:
    case CURLINFO_HTTPAUTH_AVAIL:
    case CURLINFO_PROXYAUTH_AVAIL:
    case CURLINFO_OS_ERRNO:
    case CURLINFO_NUM_CONNECTS:
    case CURLINFO_LASTSOCKET:
      (long *)result;
      rc = curl_easy_getinfo(hnd, info, &result);
      if ( rc == 0) {
	if (result == NULL) {
	  res = SCM_FALSE;
	} else {
	  res = SCM_MAKE_INT(result);
	}
      } else {
	res = SCM_FALSE;
      }
      break;
      /* double */
    case CURLINFO_TOTAL_TIME:
    case CURLINFO_NAMELOOKUP_TIME:
    case CURLINFO_CONNECT_TIME:
    case CURLINFO_PRETRANSFER_TIME:
    case CURLINFO_SIZE_UPLOAD:
    case CURLINFO_SIZE_DOWNLOAD:
    case CURLINFO_SPEED_DOWNLOAD:
    case CURLINFO_SPEED_UPLOAD:
    case CURLINFO_CONTENT_LENGTH_DOWNLOAD:
    case CURLINFO_CONTENT_LENGTH_UPLOAD:
    case CURLINFO_STARTTRANSFER_TIME:
    case CURLINFO_REDIRECT_TIME:
    case CURLINFO_APPCONNECT_TIME:
      (double *)result;
      rc = curl_easy_getinfo(hnd, info, &result);
      if ( rc == 0) {
	if (result == NULL) {
	  res = SCM_FALSE;
	} else {
	  res = SCM_MAKE_INT(result);
	}
      } else {
	res = SCM_FALSE;
      }
      break;
      /* else */
    default:
      res = SCM_FALSE;
      break;
    }
  return res;
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
    ScmCurlMClass =
      Scm_MakeForeignPointerClass(mod, "<curl-multi-base>",
				  NULL,
				  curlm_cleanup,
    				  SCM_FOREIGN_POINTER_KEEP_IDENTITY|SCM_FOREIGN_POINTER_MAP_NULL);
    ScmCurlSHClass =
      Scm_MakeForeignPointerClass(mod, "<curl-share-base>",
				  NULL,
				  curlsh_cleanup,
    				  SCM_FOREIGN_POINTER_KEEP_IDENTITY|SCM_FOREIGN_POINTER_MAP_NULL);

    ScmCurl_SListClass =
      Scm_MakeForeignPointerClass(mod, "<curl-slist>",
				  NULL,
				  NULL,
				  SCM_FOREIGN_POINTER_KEEP_IDENTITY|SCM_FOREIGN_POINTER_MAP_NULL);

    /* Register stub-generated procedures */
    Scm_Init_curllib(mod);
}



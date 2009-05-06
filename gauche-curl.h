/*
 * curl.h
 */

/* Prologue */
#ifndef GAUCHE_CURL_H
#define GAUCHE_CURL_H

#include <gauche.h>
#include <gauche/extend.h>

#include <curl/curl.h>

SCM_DECL_BEGIN

/* <curl-base> */
extern ScmClass *ScmCurlClass;
#define SCMCURL_P(obj) SCM_XTYPEP(obj, ScmCurlClass)
#define SCMCURL_UNBOX(obj) SCM_FOREIGN_POINTER_REF(CURL*, obj)
#define SCMCURL_BOX(ptr) Scm_MakeForeignPointer(ScmCurlClass, ptr)

/* <curl-slist> */
extern ScmClass *ScmCurl_SListClass;
#define SCMCURL_SLIST_P(obj) SCM_XTYPEP(obj, ScmCurl_SListClass)
#define SCMCURL_SLIST_UNBOX(obj) SCM_FOREIGN_POINTER_REF(struct curl_slist*, obj)
#define SCMCURL_SLIST_BOX(ptr) Scm_MakeForeignPointer(ScmCurl_SListClass, ptr)

/* bind stdio to port */
//CURLOPT_WRITEFUNCTION 
extern size_t write_to_port(void *buffer, size_t sz, size_t nmemb, void *stream);

//CURLOPT_READFUNCTION
extern size_t read_from_port(void *buffer, size_t sz, size_t nmemb, void *stream);

extern struct curl_slist *list_to_curl_slist (ScmObj ls);

extern ScmObj curl_slist_to_list (struct curl_slist *slist);

/* CURLOPT_IOCTLFUNCTION */
/* CURLOPT_SEEKFUNCTION */
/* CURLOPT_SOCKOPTFUNCTION */
/* CURLOPT_OPENSOCKETFUNCTION */
/* CURLOPT_PROGRESSFUNCTION */
/* CURLOPT_HEADERFUNCTION */

/*
 * The following entry is a dummy one.
 * Replace it for your declarations.
 */

extern ScmObj test_curl(void);
extern ScmObj curl_version_info_list(void);

/* Epilogue */
SCM_DECL_END

#endif  /* GAUCHE_CURL_H */

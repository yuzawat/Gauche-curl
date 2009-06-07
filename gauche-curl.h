/*-*- coding: utf-8 -*-*/
/*
 * curl.h
 */

/* Prologue */
#ifndef GAUCHE_CURL_H
#define GAUCHE_CURL_H

#include <gauche.h>
#include <gauche/extend.h>
#include <fcntl.h>

#include <curl/curl.h>

SCM_DECL_BEGIN

/* <curl-base> */
extern ScmClass *ScmCurlClass;
#define SCMCURL_P(obj) SCM_XTYPEP(obj, ScmCurlClass)
#define SCMCURL_UNBOX(obj) SCM_FOREIGN_POINTER_REF(CURL*, obj)
#define SCMCURL_BOX(ptr) Scm_MakeForeignPointer(ScmCurlClass, ptr)

/* <curl-multi-base> */
extern ScmClass *ScmCurlMClass;
#define SCMCURLM_P(obj) SCM_XTYPEP(obj, ScmCurlMClass)
#define SCMCURLM_UNBOX(obj) SCM_FOREIGN_POINTER_REF(CURLM*, obj)
#define SCMCURLM_BOX(ptr) Scm_MakeForeignPointer(ScmCurlMClass, ptr)

/* <curl-share-base> */
extern ScmClass *ScmCurlSHClass;
#define SCMCURLSH_P(obj) SCM_XTYPEP(obj, ScmCurlSHClass)
#define SCMCURLSH_UNBOX(obj) SCM_FOREIGN_POINTER_REF(CURLSH*, obj)
#define SCMCURLSH_BOX(ptr) Scm_MakeForeignPointer(ScmCurlSHClass, ptr)

/* <curl-slist> */
extern ScmClass *ScmCurl_SListClass;
#define SCMCURL_SLIST_P(obj) SCM_XTYPEP(obj, ScmCurl_SListClass)
#define SCMCURL_SLIST_UNBOX(obj) SCM_FOREIGN_POINTER_REF(struct curl_slist*, obj)
#define SCMCURL_SLIST_BOX(ptr) Scm_MakeForeignPointer(ScmCurl_SListClass, ptr)

//CURLOPT_WRITEFUNCTION 
extern size_t write_to_port(void *buffer, size_t sz, size_t nmemb, void *scm_port);

//CURLOPT_READFUNCTION
extern size_t read_from_port(void *buffer, size_t sz, size_t nmemb, void *stream);

extern ScmObj curl_open_file(CURL* hnd, int type, const char *fn);
extern ScmObj curl_open_port(CURL* hnd, int type, ScmObj *scm_port);

//conver from/to curl_slist to/from sheme list
extern struct curl_slist *list_to_curl_slist (ScmObj ls);
extern ScmObj curl_slist_to_list (struct curl_slist *slist);

/* CURLOPT_IOCTLFUNCTION */
/* CURLOPT_SEEKFUNCTION */
/* CURLOPT_SOCKOPTFUNCTION */
/* CURLOPT_OPENSOCKETFUNCTION */
/* CURLOPT_PROGRESSFUNCTION */

extern ScmObj curl_version_info_list(void);
ScmObj _curl_easy_getinfo(CURL* hnd, int info);

typedef struct ScmCurlErrorRec {
  ScmError common;
  int error_code;
} ScmCurlError;

SCM_CLASS_DECL(ScmCurlErrorClass);
#define SCM_CLASS_CURL_ERROR  (&ScmCurlErrorClass)
#define SCMCURL_ERROR(obj)   ((ScmCurlError*)(obj))
#define SCMCURL_ERROR_P(obj) SCM_ISA(obj, SCM_CLASS_CURL_ERROR)

extern ScmObj ScmMakeCurlError(ScmObj message, int error_code);
//extern void ScmCurlError(CURL *hnd, const char *msg, ...);

extern const char *curlErrStr(int rc);

static const char *curl_tmp_file(void);

/* Epilogue */
SCM_DECL_END

#endif  /* GAUCHE_CURL_H */

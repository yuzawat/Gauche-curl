/*-*- coding: utf-8 -*-*/
/*
 * curl.h
 *
 * Last Updated: "2010/05/08 23:37.20"
 *
 * Copyright (c) 2010  yuzawat <suzdalenator@gmail.com>
 */

/* Prologue */
#ifndef GAUCHE_CURL_H
#define GAUCHE_CURL_H

#include <gauche.h>
#include <gauche/extend.h>
#include <gauche/system.h>
#include <fcntl.h>
#include <sys/select.h>

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

/* <curl-file> */
extern ScmClass *ScmCurl_FileClass;
#define SCMCURL_FILE_P(obj) SCM_XTYPEP(obj, ScmCurl_FileClass)
#define SCMCURL_FILE_UNBOX(obj) SCM_FOREIGN_POINTER_REF(FILE*, obj)
#define SCMCURL_FILE_BOX(ptr) Scm_MakeForeignPointer(ScmCurl_FileClass, ptr)

/* <curl-progress> */
typedef struct curl_progress_t {
  double progress;
  double total;
} CURLPROGRESS;
extern ScmClass *ScmCurl_ProgressClass;
#define SCMCURL_PROGRESS_P(obj) SCM_XTYPEP(obj, ScmCurl_FileClass)
#define SCMCURL_PROGRESS_UNBOX(obj) SCM_FOREIGN_POINTER_REF(CURLPROGRESS*, obj)
#define SCMCURL_PROGRESS_BOX(ptr) Scm_MakeForeignPointer(ScmCurl_ProgressClass, ptr)

/* <curl-msg> */
extern ScmClass *ScmCurl_MsgClass;
#define SCMCURL_MSG_P(obj) SCM_XTYPEP(obj, ScmCurl_MsgClass)
#define SCMCURL_MSG_UNBOX(obj) SCM_FOREIGN_POINTER_REF(CURLMsg*, obj)
#define SCMCURL_MSG_BOX(ptr) Scm_MakeForeignPointer(ScmCurl_MsgClass, ptr)

/* I/O  */
extern FILE *curl_open_file(CURL *hnd, int type, const char *fn);
extern ScmObj curl_open_port(CURL *hnd, int type, ScmObj *scm_port);
extern ScmObj curl_close_file(FILE *fp);

/* convert from/to curl_slist to/from sheme list */
extern struct curl_slist *list_to_curl_slist (ScmObj ls);
extern ScmObj curl_slist_to_list (void *slist);

/* CURLOPT_WRITEFUNCTION */
extern size_t write_to_port(void *buffer, size_t sz, size_t nmemb, void *scm_port);
/* CURLOPT_READFUNCTION */
extern size_t read_from_port(void *buffer, size_t sz, size_t nmemb, void *scm_port);
/* CURLOPT_IOCTLFUNCTION */
/* CURLOPT_SEEKFUNCTION */
/* CURLOPT_SOCKOPTFUNCTION */
int _set_socket_option(void *clientp, curl_socket_t curlfd, curlsocktype purpose);
/* CURLOPT_OPENSOCKETFUNCTION */
/* CURLOPT_PROGRESSFUNCTION */
int _set_progress (CURLPROGRESS *prog, double dltotal, double dlnow, double ultotal, double ulnow);
int _show_progress (CURLPROGRESS *prog, double dltotal, double dlnow, double ultotal, double ulnow);

/* misc */
extern ScmObj curl_version_info_list(void);
ScmObj _curl_easy_getinfo(CURL* hnd, int info);

/* Epilogue */
SCM_DECL_END

#endif  /* GAUCHE_CURL_H */

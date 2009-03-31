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

/* <curl-version-info> */
extern ScmClass *ScmCurl_VersionInfoClass;
#define SCMCURL_VERSIONINFO_P(obj) SCM_XTYPEP(obj, Scmcurl_VersionInfoClass)
#define SCMCURL_VERSIONINFO_UNBOX(obj) SCM_FOREIGN_POINTER_REF(curl_version_info_data*, obj)
#define SCMCURL_VERSIONINFO_BOX(ptr) Scm_MakeForeignPointer(ScmCurl_VersionInfoClass, ptr)

/* bind stdio to port */
extern size_t write_to_port(void *buffer, size_t sz, size_t nmemb, void *stream);
extern size_t read_from_port(void *buffer, size_t sz, size_t nmemb, void *stream);
extern size_t write_to_err_port(void *buffer, size_t sz, size_t nmemb, void *stream);

/*
 * The following entry is a dummy one.
 * Replace it for your declarations.
 */

extern ScmObj test_curl(void);

/* Epilogue */
SCM_DECL_END

#endif  /* GAUCHE_CURL_H */

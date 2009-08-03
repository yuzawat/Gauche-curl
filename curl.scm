;;; -*- coding: utf-8; mode: scheme -*-
;;;
;;; libcurl binding for gauche
;;;  libcurl: <http://curl.haxx.se/libcurl/>
;;;
;;; Last Updated: "2009/08/03 15:17.23"
;;;
;;;  Copyright (c) 2009  yuzawat <suzdalenator@gmail.com>


;;; Example
;;;
;;; (let* ((c (make <curl> :url "http://example.tld/test/" 
;;; 		:options '("-L" "--compressd" "--header=HOGE0: HOGE0,HOGE1: HOGE1")))
;;;        (output-str-port (curl-open-output-port c))
;;;        (header-str-port (curl-open-header-port c)))
;;;   (c)
;;;   (values  
;;;    (cdr (assq 'RESPONSE_CODE (curl-getinfo c)))
;;;    (curl-headers->alist (get-output-string header-str-port) -1)
;;;    (get-output-string output-str-port)))

(define-module curl
  (use gauche.mop.singleton)
  (use gauche.parseopt)
  (use gauche.version)
  (use rfc.822)
  (use rfc.uri)
  (use srfi-1)
  (use util.list)
  (export 
   <curl>
   <curl-multi>
   <curl-base>

   ;; bare functions
   curl-global-init
   curl-global-cleanup

   curl-easy-init
   curl-easy-cleanup
   curl-easy-setopt
   curl-easy-perform
   curl-easy-reset
   curl-easy-duphandle
   curl-easy-getinfo
   curl-easy-strerror
   curl-easy-escape
   curl-easy-unescape
   curl-free
   curl-getenv
   curl-getdate
   curl-easy-send
   curl-easy-recv

   curl-multi-init
   curl-multi-cleanup
   curl-multi-add-handle
   curl-multi-remove-handle

   curl-share-init
   curl-share-setopt
   curl-share-strerror

   curl-version
   curl-version-info

   curl-open-file
   curl-open-port
   curl-close-file

   list->curl-slist
   curl-slist->list

   ;; procedure
   curl-setopt!
   curl-perform
   curl-getinfo
   curl-cleanup!
   curl-reset!
   curl-strerror
   curl-open-output-file
   curl-open-input-file
   curl-open-header-file
   curl-open-error-file
   curl-open-output-port
   curl-open-input-port
   curl-open-header-port
   curl-headers->alist

   http-get
   http-head
   http-post
   http-put
   http-delete

   ;; curl response code
   CURLE_OK
   CURLE_UNSUPPORTED_PROTOCOL
   CURLE_FAILED_INIT
   CURLE_URL_MALFORMAT
   CURLE_COULDNT_RESOLVE_PROXY
   CURLE_COULDNT_RESOLVE_HOST
   CURLE_COULDNT_CONNECT
   CURLE_FTP_WEIRD_SERVER_REPLY
   CURLE_REMOTE_ACCESS_DENIED
   CURLE_FTP_WEIRD_PASS_REPLY
   CURLE_FTP_WEIRD_PASV_REPLY
   CURLE_FTP_WEIRD_227_FORMAT
   CURLE_FTP_CANT_GET_HOST
   CURLE_FTP_COULDNT_SET_TYPE
   CURLE_PARTIAL_FILE
   CURLE_FTP_COULDNT_RETR_FILE
   CURLE_QUOTE_ERROR
   CURLE_HTTP_RETURNED_ERROR
   CURLE_WRITE_ERROR
   CURLE_UPLOAD_FAILED
   CURLE_READ_ERROR
   CURLE_OUT_OF_MEMORY
   CURLE_OPERATION_TIMEDOUT
   CURLE_FTP_PORT_FAILED
   CURLE_FTP_COULDNT_USE_REST
   CURLE_RANGE_ERROR
   CURLE_HTTP_POST_ERROR
   CURLE_SSL_CONNECT_ERROR
   CURLE_BAD_DOWNLOAD_RESUME
   CURLE_FILE_COULDNT_READ_FILE
   CURLE_LDAP_CANNOT_BIND
   CURLE_LDAP_SEARCH_FAILED
   CURLE_FUNCTION_NOT_FOUND
   CURLE_ABORTED_BY_CALLBACK
   CURLE_BAD_FUNCTION_ARGUMENT
   CURLE_INTERFACE_FAILED
   CURLE_TOO_MANY_REDIRECTS
   CURLE_UNKNOWN_TELNET_OPTION
   CURLE_TELNET_OPTION_SYNTAX
   CURLE_PEER_FAILED_VERIFICATION
   CURLE_GOT_NOTHING
   CURLE_SSL_ENGINE_NOTFOUND
   CURLE_SSL_ENGINE_SETFAILED
   CURLE_SEND_ERROR
   CURLE_RECV_ERROR
   CURLE_SSL_CERTPROBLEM
   CURLE_SSL_CIPHER
   CURLE_SSL_CACERT
   CURLE_BAD_CONTENT_ENCODING
   CURLE_LDAP_INVALID_URL
   CURLE_FILESIZE_EXCEEDED
   CURLE_USE_SSL_FAILED
   CURLE_SEND_FAIL_REWIND
   CURLE_SSL_ENGINE_INITFAILED
   CURLE_LOGIN_DENIED
   CURLE_TFTP_NOTFOUND
   CURLE_TFTP_PERM
   CURLE_REMOTE_DISK_FULL
   CURLE_TFTP_ILLEGAL
   CURLE_TFTP_UNKNOWNID
   CURLE_REMOTE_FILE_EXISTS
   CURLE_TFTP_NOSUCHUSER
   CURLE_CONV_FAILED
   CURLE_CONV_REQD
   CURLE_SSL_CACERT_BADFILE
   CURLE_REMOTE_FILE_NOT_FOUND
   CURLE_SSH
   CURLE_SSL_SHUTDOWN_FAILED
   CURLE_AGAIN

   ;; global flags
   CURL_GLOBAL_ALL
   CURL_GLOBAL_SSL
   CURL_GLOBAL_WIN32
   CURL_GLOBAL_NOTHING

   ;; curl option
   CURLOPT_FILE
   CURLOPT_URL
   CURLOPT_PORT
   CURLOPT_PROXY
   CURLOPT_NOPROXY
   CURLOPT_USERPWD
   CURLOPT_PROXYUSERPWD
   CURLOPT_RANGE
   CURLOPT_INFILE
   CURLOPT_ERRORBUFFER
   CURLOPT_WRITEFUNCTION
   CURLOPT_WRITEDATA
   CURLOPT_READFUNCTION
   CURLOPT_READDATA
   CURLOPT_TIMEOUT
   CURLOPT_INFILESIZE
   CURLOPT_POSTFIELDS
   CURLOPT_REFERER
   CURLOPT_FTPPORT
   CURLOPT_USERAGENT
   CURLOPT_LOW_SPEED_LIMIT
   CURLOPT_LOW_SPEED_TIME
   CURLOPT_RESUME_FROM
   CURLOPT_COOKIE
   CURLOPT_HTTPHEADER
   CURLOPT_HTTPPOST
   CURLOPT_SSLCERT
   CURLOPT_KEYPASSWD
   CURLOPT_CRLF
   CURLOPT_QUOTE
   CURLOPT_WRITEHEADER
   CURLOPT_COOKIEFILE
   CURLOPT_SSLVERSION
   CURLOPT_TIMECONDITION
   CURLOPT_TIMEVALUE
   CURLOPT_CUSTOMREQUEST
   CURLOPT_STDERR
   CURLOPT_POSTQUOTE
   CURLOPT_WRITEINFO
   CURLOPT_VERBOSE
   CURLOPT_HEADER
   CURLOPT_NOPROGRESS
   CURLOPT_NOBODY
   CURLOPT_FAILONERROR
   CURLOPT_UPLOAD
   CURLOPT_POST
   CURLOPT_DIRLISTONLY
   CURLOPT_APPEND
   CURLOPT_NETRC
   CURLOPT_FOLLOWLOCATION
   CURLOPT_TRANSFERTEXT
   CURLOPT_PUT
   CURLOPT_PROGRESSFUNCTION
   CURLOPT_PROGRESSDATA
   CURLOPT_AUTOREFERER
   CURLOPT_PROXYPORT
   CURLOPT_POSTFIELDSIZE
   CURLOPT_HTTPPROXYTUNNEL
   CURLOPT_INTERFACE
   CURLOPT_KRBLEVEL
   CURLOPT_SSL_VERIFYPEER
   CURLOPT_CAINFO
   CURLOPT_MAXREDIRS
   CURLOPT_FILETIME
   CURLOPT_TELNETOPTIONS
   CURLOPT_MAXCONNECTS
   CURLOPT_CLOSEPOLICY
   CURLOPT_FRESH_CONNECT
   CURLOPT_FORBID_REUSE
   CURLOPT_RANDOM_FILE
   CURLOPT_EGDSOCKET
   CURLOPT_CONNECTTIMEOUT
   CURLOPT_HEADERFUNCTION
   CURLOPT_HTTPGET
   CURLOPT_SSL_VERIFYHOST
   CURLOPT_COOKIEJAR
   CURLOPT_SSL_CIPHER_LIST
   CURLOPT_HTTP_VERSION
   CURLOPT_FTP_USE_EPSV
   CURLOPT_SSLCERTTYPE
   CURLOPT_SSLKEY
   CURLOPT_SSLKEYTYPE
   CURLOPT_SSLENGINE
   CURLOPT_SSLENGINE_DEFAULT
   CURLOPT_DNS_USE_GLOBAL_CACHE
   CURLOPT_DNS_CACHE_TIMEOUT
   CURLOPT_PREQUOTE
   CURLOPT_DEBUGFUNCTION
   CURLOPT_DEBUGDATA
   CURLOPT_COOKIESESSION
   CURLOPT_CAPATH
   CURLOPT_BUFFERSIZE
   CURLOPT_NOSIGNAL
   CURLOPT_SHARE
   CURLOPT_PROXYTYPE
   CURLOPT_ENCODING
   CURLOPT_PRIVATE
   CURLOPT_HTTP200ALIASES
   CURLOPT_UNRESTRICTED_AUTH
   CURLOPT_FTP_USE_EPRT
   CURLOPT_HTTPAUTH
   CURLOPT_SSL_CTX_FUNCTION
   CURLOPT_SSL_CTX_DATA
   CURLOPT_FTP_CREATE_MISSING_DIRS
   CURLOPT_PROXYAUTH
   CURLOPT_FTP_RESPONSE_TIMEOUT
   CURLOPT_IPRESOLVE
   CURLOPT_MAXFILESIZE
   CURLOPT_INFILESIZE_LARGE
   CURLOPT_RESUME_FROM_LARGE
   CURLOPT_MAXFILESIZE_LARGE
   CURLOPT_NETRC_FILE
   CURLOPT_USE_SSL
   CURLOPT_POSTFIELDSIZE_LARGE
   CURLOPT_TCP_NODELAY
   CURLOPT_FTPSSLAUTH
   CURLOPT_IOCTLFUNCTION
   CURLOPT_IOCTLDATA
   CURLOPT_FTP_ACCOUNT
   CURLOPT_COOKIELIST
   CURLOPT_IGNORE_CONTENT_LENGTH
   CURLOPT_FTP_SKIP_PASV_IP
   CURLOPT_FTP_FILEMETHOD
   CURLOPT_LOCALPORT
   CURLOPT_LOCALPORTRANGE
   CURLOPT_CONNECT_ONLY
   CURLOPT_CONV_FROM_NETWORK_FUNCTION
   CURLOPT_CONV_TO_NETWORK_FUNCTION
   CURLOPT_CONV_FROM_UTF8_FUNCTION
   CURLOPT_MAX_SEND_SPEED_LARGE
   CURLOPT_MAX_RECV_SPEED_LARGE
   CURLOPT_FTP_ALTERNATIVE_TO_USER
   CURLOPT_SOCKOPTFUNCTION
   CURLOPT_SOCKOPTDATA
   CURLOPT_SSL_SESSIONID_CACHE
   CURLOPT_SSH_AUTH_TYPES
   CURLOPT_SSH_PUBLIC_KEYFILE
   CURLOPT_SSH_PRIVATE_KEYFILE
   CURLOPT_FTP_SSL_CCC
   CURLOPT_TIMEOUT_MS
   CURLOPT_CONNECTTIMEOUT_MS
   CURLOPT_HTTP_TRANSFER_DECODING
   CURLOPT_HTTP_CONTENT_DECODING
   CURLOPT_NEW_FILE_PERMS
   CURLOPT_NEW_DIRECTORY_PERMS
   CURLOPT_POSTREDIR
   CURLOPT_SSH_HOST_PUBLIC_KEY_MD5
   CURLOPT_OPENSOCKETFUNCTION
   CURLOPT_OPENSOCKETDATA
   CURLOPT_COPYPOSTFIELDS
   CURLOPT_PROXY_TRANSFER_MODE
   CURLOPT_SEEKFUNCTION
   CURLOPT_SEEKDATA
   CURLOPT_CRLFILE
   CURLOPT_ISSUERCERT
   CURLOPT_ADDRESS_SCOPE
   CURLOPT_CERTINFO
   CURLOPT_USERNAME
   CURLOPT_PASSWORD
   CURLOPT_PROXYUSERNAME
   CURLOPT_PROXYPASSWORD

   ;; curl information code
   CURLINFO_NONE
   CURLINFO_EFFECTIVE_URL
   CURLINFO_RESPONSE_CODE
   CURLINFO_TOTAL_TIME
   CURLINFO_NAMELOOKUP_TIME
   CURLINFO_CONNECT_TIME
   CURLINFO_PRETRANSFER_TIME
   CURLINFO_SIZE_UPLOAD
   CURLINFO_SIZE_DOWNLOAD
   CURLINFO_SPEED_DOWNLOAD
   CURLINFO_SPEED_UPLOAD
   CURLINFO_HEADER_SIZE
   CURLINFO_REQUEST_SIZE
   CURLINFO_SSL_VERIFYRESULT
   CURLINFO_FILETIME
   CURLINFO_CONTENT_LENGTH_DOWNLOAD
   CURLINFO_CONTENT_LENGTH_UPLOAD
   CURLINFO_STARTTRANSFER_TIME
   CURLINFO_CONTENT_TYPE
   CURLINFO_REDIRECT_TIME
   CURLINFO_REDIRECT_COUNT
   CURLINFO_PRIVATE
   CURLINFO_HTTP_CONNECTCODE
   CURLINFO_HTTPAUTH_AVAIL
   CURLINFO_PROXYAUTH_AVAIL
   CURLINFO_OS_ERRNO
   CURLINFO_NUM_CONNECTS
   CURLINFO_SSL_ENGINES
   CURLINFO_COOKIELIST
   CURLINFO_LASTSOCKET
   CURLINFO_FTP_ENTRY_PATH
   CURLINFO_REDIRECT_URL
   CURLINFO_PRIMARY_IP
   CURLINFO_APPCONNECT_TIME
   CURLINFO_CERTINFO
   CURLINFO_CONDITION_UNMET
   CURLINFO_LASTONE

   CURL_HTTP_VERSION_NONE
   CURL_HTTP_VERSION_1_0
   CURL_HTTP_VERSION_1_1

   ;; curl current version 
   CURLVERSION_NOW

   ;; CURLMcode
   CURLM_CALL_MULTI_PERFORM
   CURLM_OK
   CURLM_BAD_HANDLE
   CURLM_BAD_EASY_HANDLE
   CURLM_OUT_OF_MEMORY
   CURLM_INTERNAL_ERROR
   CURLM_BAD_SOCKET
   CURLM_UNKNOWN_OPTION
   CURLM_LAST

   ;; CURLMSG
   CURLMSG_NONE
   CURLMSG_DONE
   CURLMSG_LAST

   ;; CURLSHcode
   CURLSHE_OK
   CURLSHE_BAD_OPTION
   CURLSHE_IN_USE
   CURLSHE_INVALID
   CURLSHE_NOMEM
   CURLSHE_LAST

   ;; CURLSHoption
   CURLSHOPT_NONE
   CURLSHOPT_SHARE
   CURLSHOPT_UNSHARE
   CURLSHOPT_LOCKFUNC
   CURLSHOPT_UNLOCKFUNC
   CURLSHOPT_USERDATA
   CURLSHOPT_LAST

   ;; Proxy type
   CURLPROXY_HTTP
   CURLPROXY_HTTP_1_0
   CURLPROXY_SOCKS4
   CURLPROXY_SOCKS5
   CURLPROXY_SOCKS4A
   CURLPROXY_SOCKS5_HOSTNAME 

   ;; IP resolve option
   CURL_IPRESOLVE_WHATEVER
   CURL_IPRESOLVE_V4
   CURL_IPRESOLVE_V6

   ;; SSH auth type
   CURLSSH_AUTH_PUBLICKEY
   CURLSSH_AUTH_PASSWORD
   CURLSSH_AUTH_HOST
   CURLSSH_AUTH_KEYBOARD
   CURLSSH_AUTH_ANY
   CURLSSH_AUTH_DEFAULT

   ;; FTP Method type
   CURLFTPMETHOD_MULTICWD
   CURLFTPMETHOD_NOCWD
   CURLFTPMETHOD_SINGLECWD

   ;; FTP use SSL option 
   CURLUSESSL_NONE
   CURLUSESSL_TRY
   CURLUSESSL_CONTROL
   CURLUSESSL_ALL

   ;; FTP Auth type
   CURLFTPAUTH_DEFAULT
   CURLFTPAUTH_SSL
   CURLFTPAUTH_TLS

   ;; FTP SSL CCC option
   CURLFTPSSL_CCC_NONE
   CURLFTPSSL_CCC_PASSIVE
   CURLFTPSSL_CCC_ACTIVE

   ;; SSL version
   CURL_SSLVERSION_DEFAULT
   CURL_SSLVERSION_TLSv1
   CURL_SSLVERSION_SSLv2
   CURL_SSLVERSION_SSLv3

   ;; time condition value
   CURL_TIMECOND_NONE
   CURL_TIMECOND_IFMODSINCE
   CURL_TIMECOND_IFUNMODSINCE
   CURL_TIMECOND_LASTMOD


   )
  )
(select-module curl)

;; Loads extension
(dynamic-load "curl")

;; global init
(curl-global-init CURL_GLOBAL_ALL)
(define curl-share-enable #t)

;; classes
(define-class <curl-meta> ()
  ((handler :allocation :instance
	    :accessor handler-of)
   (rc :allocation :instance
       :accessor rc-of
       :init-value #f)))

(define-class <curl> (<curl-meta>)
  ((url :allocation :instance
	:init-keyword :url
	:init-value ""
	:accessor url-of)
   (options :allocation :instance
	    :init-keyword :options
	    :init-value ""
	    :accessor options-of)
   (http-headers :allocation :instance
		 :init-value '()
		 :accessor http-headers-of)))

(define-class <curl-share> (<curl-meta> <singleton-mixin>)
  ())

(define-class <curl-multi> (<curl-meta>)
  ((handlers :allocation :instance
	:init-keyword :handlers
	:accessor handlers-of)
   (options :allocation :instance
	   :init-keyword :options
	   :init-value ""
	   :accessor options-of)))

(define-method initialize ((curl <curl>) initargs)
  (next-method)
  (slot-set! curl 'handler (curl-easy-init))
  (when (slot-bound? curl 'url)
    (curl-setopt! curl CURLOPT_URL (url-of curl)))
  (when (slot-bound? curl 'options)
    (%easy-options curl (options-of curl))))

(define-method initialize ((share <curl-share>) initargs)
  (next-method)
  (slot-set! share 'handler (curl-share-init))
  (curl-share-setopt (handler-of share) CURLSHOPT_SHARE CURL_LOCK_DATA_COOKIE)
  (curl-share-setopt (handler-of share) CURLSHOPT_SHARE CURL_LOCK_DATA_DNS))

(define-method object-apply ((curl <curl>))
  (curl-perform curl))


;; condition
(define-condition-type <curl-error> <error> #f)


;; utils
; libcurl version check
(define (vc numstr)
  (let1 version (cdr (assoc "version" (curl-version-info)))
    (version>? version numstr)))
; libcurl features check
(define (fc str)
  (let1 features (cdr (assoc "features" (curl-version-info)))
    (if ((string->regexp str) features) #t #f)))
; libcurl support protocols check
(define (pc str)
  (let1 protocols (cdr (assoc "protocols" (curl-version-info)))
    (if ((string->regexp str) protocols) #t #f)))
; URL scheme check
(define (sc str url)
  (let1 scheme (values-ref (uri-parse url) 0)
    (if ((string->regexp str) scheme) #t #f)))


; parse options
(define-method %easy-options ((curl <curl>) args)
  (let ((argls (if (string? args) (string-split args #/\s+/) args))
	(hnd (handler-of curl))
	(_ curl-setopt!))
    (let-args argls
	((user-agent "A|user-agent=s" #f)
	 (location "L|location" #f)
	 (location-trusted "location-trusted" #f)
	 (request "X|request=s" #f)
	 (output "o|output=s" #f)
	 (remote-name "O|remote-name" #f)
	 (remote-time "R|remote-time=s" #f)
	 (dump-header "D|dump-header=s" #f)
	 (stderr "stderr=s" #f)
	 (verbose "v|verbose" #f)
	 (ignore-content-length "ignore-content-length" #f)
	 (referer "e|referer=s" #f)
	 (interface "interface=s" #f)
	 (urlstr "url=s" #f)
	 (tcp-nodelay "tcp-nodelay" #f)
	 (compressed "compressed"   #f)
	 (user "u|user=s" #f)
	 (basic "basic" #f)
	 (digest "digest" #f)
	 (negotiate "negotiate" #f)
	 (ntlm "ntlm" #f)
	 (anyauth "anyauth" #f)
	 (fail "f|fail" #f)
	 (include "i|include" #f)
	 (head "I|head" #f)
	 (get "G|get" #f)
	 (header "H|header=s" #f)
	 (proxy "x|proxy=s" #f)
	 (proxy1.0 "proxy1_0=s" #f)
	 (socks4 "socks4=s" #f)
	 (socks4a "socks4a=s" #f)
	 (socks5 "socks5=s" #f)
	 (socks5-gssapi-nec "socks5-gssapi-nec" #f)
	 (socks5-gssapi-service "socks5-gssapi-service=s" #f)
	 (socks5-hostname "socks5-hostname=s" #f)
	 (proxytunnel "p|proxytunnel" #f)
	 (noproxy "noproxy=s" #f)
	 (proxy-user "U|proxy-user=s" #f)
	 (proxy-anyauth "proxy-anyauth" #f)
	 (proxy-basic "proxy-basic" #f)
	 (proxy-digest "proxy-digest" #f)
	 (proxy-negotiate "proxy-negotiate" #f)
	 (proxy-ntlm "proxy-ntlm" #f)
	 (post301 "post301" #f)
	 (post302 "post302" #f)
	 (upload-file "T|upload-file=s" #f)
	 (junk-session-cookies "j|junk-session-cookies" #f)
	 (cookie "b|cookie=s" #f)
	 (cookie-jar "c|cookie-jar=s" #f)
	 (data "d|data|data-ascii=s" #f)
	 (data-binary "data-binary=s" #f)
	 (data-urlencode "data-urlencode=s" #f)
	 (max-filesize "max-filesize=i" #f)
	 (max-redirs "max-redirs=i" #f)
	 (connect-timeout "connect-timeout=i" #f)
	 (max-time "m|max-time=i" #f)
	 (http1.0 "0|http1_0" #f)
	 (raw "raw" #f)
	 (time-cond "z|time-cond=s" #f)
	 (range "r|range=s" #f)
	 (local-port "local-port=s" #f)
	 (ipv4 "4|ipv4" #f)
	 (ipv6 "6|ipv6" #f)
	 (tlsv1 "1|tlsv1" #f)
	 (sslv2 "2|sslv2" #f)
	 (sslv3 "3|sslv3" #f)
	 (cacert "cacert=s" #f)
	 (capath "capath=s" #f)
	 (cert-type "cert-type=s" #f) 
	 (ciphers "ciphers=s" #f)
	 (random-file "random-file=s" #f)
	 (egd-file "egd-file=s" #f)
	 (engine "engine=s" #f)
	 (sessionid "sessionid" #f)
	 (no-sessionid "no-sessionid" #f)
	 (cert "E|cert=s" #f)
	 (key "key=s" #f)
	 (key-type "key-type=s" #f)
	 (pass "pass=s" #f)
	 (insecure "k|insecure" #f)
	 (pubkey "pubkey=s" #f)
	 (hostpubmd5 "hostpubmd5=s" #f)
	 (ftp-port "P|ftp-port=s" #f)
	 (ftp-pasv "ftp-pasv" #f)
	 (quote "Q|quote=s" #f)
	 (list-only "l|list-only" #f)
	 (append "a|append" #f)
	 (ftp-create-dirs "ftp-create-dirs" #f)
	 (use-ascii "B|use-ascii" #f)
	 (crlf "crlf" #f)
	 (disable-eprt "disable-eprt" #f)
	 (disable-epsv "disable-epsv" #f)
	 (no-eprt "no-eprt" #f)
	 (no-epsv "no-epsv" #f)
	 (eprt "eprt" #f)
	 (epsv "epsv" #f)
	 (ftp-skip-pasv-ip "ftp-skip-pasv-ip" #f)
	 (ftp-alternative-to-user "ftp-alternative-to-user=s" #f)
	 (ftp-account "ftp-account=s" #f)
	 (ftp-method "ftp-method=s"#f )
	 (krb "krb=s" #f)
	 (ftp-ssl "ftp-ssl" #f)
	 (ftp-ssl-control "ftp-ssl-control" #f)
	 (ftp-ssl-reqd "ftp-ssl-reqd" #f)
	 (ftp-ssl-ccc "ftp-ssl-ccc" #f)
	 (ftp-ssl-ccc-mode "ftp-ssl-ccc-mode=s" #f)
	 (telnet-option "t|telnet-option=s" #f))
      ;; common
      (when urlstr (begin (_ curl CURLOPT_URL urlstr) (set! (url-of curl) urlstr)))
      (when curl-share-enable (_ curl CURLOPT_SHARE (handler-of (make <curl-share>))))
      (if connect-timeout (_ curl CURLOPT_CONNECTTIMEOUT connect-timeout) (_ curl CURLOPT_CONNECTTIMEOUT 0))
      (if max-time (_ curl CURLOPT_TIMEOUT max-time) (_ curl CURLOPT_TIMEOUT 0))
      (when ipv4 (_ curl CURLOPT_IPRESOLVE CURL_IPRESOLVE_V4))
      (when (fc "IPv6") (when ipv6 (_ curl CURLOPT_IPRESOLVE CURL_IPRESOLVE_V6)))
      (if range
	  (_ curl CURLOPT_RANGE range)
	  (_ curl CURLOPT_RANGE #f))
      (when (vc "7.15.2")
	(when local-port
	  (cond ((#/^(\d+)(\-(\d+))?$/ local-port) 
		 => (lambda (m) 
		      (begin
			(_ curl CURLOPT_LOCALPORT (string->number (m 1)))
			(when (m 3) (_ curl CURLOPT_LOCALPORTRANGE (string->number (m 3)))))))
		(else <curl-error> :message "local port range is invalid."))))
      ;; debug
      (if verbose (_ curl CURLOPT_VERBOSE 1) (_ curl CURLOPT_VERBOSE 0))
      (when stderr (curl-open-file hnd CURLOPT_STDERR stderr))
      ;; http 
      (if user-agent (_ curl CURLOPT_USERAGENT user-agent) 
	  (_ curl CURLOPT_USERAGENT (string-append "Gauche/" (gauche-version) " " (curl-version))))
      (if location (_ curl CURLOPT_FOLLOWLOCATION 1) (_ curl CURLOPT_FOLLOWLOCATION 0)) 
      (if location-trusted (_ curl CURLOPT_UNRESTRICTED_AUTH 1) (_ curl CURLOPT_UNRESTRICTED_AUTH 0))
      (if max-redirs (_ curl CURLOPT_MAXREDIRS max-redirs) (_ curl CURLOPT_MAXREDIRS -1))
      (if request (_ curl CURLOPT_CUSTOMREQUEST request) (_ curl CURLOPT_CUSTOMREQUEST #f))
      (if referer
 	  (begin
	    (if (#/\;auto$/ referer) (_ curl CURLOPT_AUTOREFERER 1) (_ curl CURLOPT_AUTOREFERER 0))
	    (cond ((#/(^.+)\;auto$/ referer)
		   => (lambda (m) (unless (= (string-length (m 1)) 0) (_ curl CURLOPT_REFERER (m 1)))))))
	  (_ curl CURLOPT_REFERER #f))
      (when compressed (_ curl CURLOPT_ENCODING ""))
      (if fail (_ curl CURLOPT_FAILONERROR 1) (_ curl CURLOPT_FAILONERROR 0))
      (when get (_ curl CURLOPT_HTTPGET 1))
      (when header (_ curl CURLOPT_HTTPHEADER (string-split header #\,)))
      (if head (_ curl CURLOPT_NOBODY 1) (_ curl CURLOPT_NOBODY 0))
      (when post301 (_ curl CURLOPT_POSTREDIR CURL_REDIR_POST_301))
      (when post302 (_ curl CURLOPT_POSTREDIR CURL_REDIR_POST_302))
      (when http1.0 (_ curl CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_1_0))
      (when (vc "7.16.2")
	(when raw
	  (begin
	    (_ curl CURLOPT_HTTP_CONTENT_DECODING 0)
	    (_ curl CURLOPT_HTTP_TRANSFER_DECODING 0))))
      (when time-cond
	(cond ((#/^([\+\-\=])?(.+)$/ time-cond)
	       => (lambda (m) 
		    (let ((condition (m 1))
			  (timeval (m 2)))
		      (cond ((equal? condition "+") (_ curl CURLOPT_TIMECONDITION CURL_TIMECOND_IFMODSINCE))
			    ((equal? condition "-") (_ curl CURLOPT_TIMECONDITION CURL_TIMECOND_IFUNMODSINCE))
			    ((equal? condition "=") (_ curl CURLOPT_TIMECONDITION CURL_TIMECOND_LASTMOD))
			    (else (_ curl CURLOPT_TIMECONDITION CURL_TIMECOND_IFMODSINCE)))
		      (if (< (curl-getdate timeval) 0)
			  (if (file-exists? timeval) (_ curl CURLOPT_TIMEVALUE (sys-stat->mtime (sys-stat timeval)))
			      (_ curl CURLOPT_TIMECONDITION CURL_TIMECOND_NONE))
			  ;; FIXME: CURLOPT_TIMEVALUE is not reflected.
			  (_ curl CURLOPT_TIMEVALUE (curl-getdate timeval))))))))
      ;; output
      (if output (curl-open-output-file curl output) (curl-open-port hnd CURLOPT_WRITEDATA (current-output-port)))
      (when remote-name (curl-open-output-file curl
					       (let1 fn (sys-basename (values-ref (uri-parse (url-of curl)) 4))
						 (if (equal? fn "") "index.html" fn))))
      (if remote-time (_ curl CURLOPT_FILETIME 1) (_ curl CURLOPT_FILETIME 0))
      (when dump-header (curl-open-header-file curl dump-header))
      (when max-filesize 
	(if (fc "Largefile")
	    (_ curl CURLOPT_MAXFILESIZE_LARGE max-filesize)
	    (_ curl CURLOPT_MAXFILESIZE max-filesize)))
      (if include (_ curl CURLOPT_HEADER 1) (_ curl CURLOPT_HEADER 0))
      (if interface (_ curl CURLOPT_INTERFACE interface) (_ curl CURLOPT_INTERFACE #f))
      (if tcp-nodelay (_ curl CURLOPT_TCP_NODELAY 1) (_ curl CURLOPT_TCP_NODELAY 0))
      ;; auth
      (if user (_ curl CURLOPT_USERPWD user) (_ curl CURLOPT_USERPWD #f))
      (when basic (_ curl CURLOPT_HTTPAUTH CURLAUTH_BASIC))
      (when digest (_ curl CURLOPT_HTTPAUTH CURLAUTH_DIGEST))
      (when (fc "GSS-Negotiate") (when negotiate (_ curl CURLOPT_HTTPAUTH CURLAUTH_GSSNEGOTIATE)))
      (when (fc "NTLM") (when ntlm (_ curl CURLOPT_HTTPAUTH CURLAUTH_NTLM)))
      (when anyauth (_ curl CURLOPT_HTTPAUTH CURLAUTH_ANY))
      ;; proxy
      (if proxy 
	  (begin 
	    (_ curl CURLOPT_PROXYTYPE CURLPROXY_HTTP)
	    (_ curl CURLOPT_PROXY proxy))
	  (_ curl CURLOPT_PROXY #f))
      (when (vc "7.15.2")
	(if socks4 
	    (begin 
	      (_ curl CURLOPT_PROXYTYPE CURLPROXY_SOCKS4)
	      (_ curl CURLOPT_PROXY socks4))
	    (_ curl CURLOPT_PROXY #f))
	(when (vc "7.18.0")
	  (begin
	    (if socks4a 
		(begin 
		  (_ curl CURLOPT_PROXYTYPE CURLPROXY_SOCKS4A)
		  (_ curl CURLOPT_PROXY socks4a))
		(_ curl CURLOPT_PROXY #f))
	    (if socks5
		(begin
		  (_ curl CURLOPT_PROXYTYPE CURLPROXY_SOCKS5)
		  (_ curl CURLOPT_PROXY socks5))
		(_ curl CURLOPT_PROXY #f))
	    (if socks5-hostname
		(begin
		  (_ curl CURLOPT_PROXYTYPE CURLPROXY_SOCKS5_HOSTNAME)
		  (_ curl CURLOPT_PROXY socks5-hostname))
		(_ curl CURLOPT_PROXY #f))))
	(when (vc "7.19.0") 
	  (when proxytunnel (_ curl CURLOPT_HTTPPROXYTUNNEL 1)))
	(when (vc "7.19.4")
	  (begin
	    (if proxy1.0 
		(begin
		  (_ curl CURLOPT_PROXYTYPE CURLPROXY_HTTP_1_0)
		  (_ curl CURLOPT_PROXY proxy1.0))
		(_ curl CURLOPT_PROXY #f)))
	  (if socks5-gssapi-nec (_ curl CURLOPT_PROXYTYPE 1) (_ curl CURLOPT_PROXYTYPE 0))
	  (when socks5-gssapi-service (_ curl CURLOPT_SOCKS5_GSSAPI_SERVICE socks5-gssapi-service))
	  (if noproxy (_ curl CURLOPT_NOPROXY noproxy) (_ curl CURLOPT_NOPROXY #f)))
      (if proxy-user (_ curl CURLOPT_PROXYUSERPWD proxy-user) (_ curl CURLOPT_PROXYUSERPWD #f))
      (when proxy-anyauth (_ curl CURLOPT_PROXYAUTH CURLAUTH_ANY))
      (when proxy-basic (_ curl CURLOPT_PROXYAUTH CURLAUTH_BASIC))
      (when proxy-digest (_ curl CURLOPT_PROXYAUTH CURLAUTH_DIGEST))
      (when (fc "GSS-Negotiate") (when proxy-negotiate (_ curl CURLOPT_PROXYAUTH CURLAUTH_GSSNEGOTIATE)))
      (when (fc "NTLM") (when proxy-ntlm (_ curl CURLOPT_PROXYAUTH CURLAUTH_NTLM)))
      ;; data upload
      (when upload-file 
	(begin
	  (_ curl CURLOPT_UPLOAD 1)
	  (curl-open-input-file curl upload-file)
	  (if (fc "Largefile")
	      (_ curl CURLOPT_INFILESIZE_LARGE (slot-ref (sys-stat upload-file) 'size))
	      (_ curl CURLOPT_INFILESIZE (slot-ref (sys-stat upload-file) 'size)))
	  (when (#/^http/ (url-of curl))
	    (let1 purl (string-append  
			(url-of curl) (if (#/\/$/ (url-of curl)) "" "/") (uri-encode-string upload-file))
	      (_ curl CURLOPT_URL purl)
	      (slot-set! curl 'url url)))))
      (when data
	(begin
	  (_ curl CURLOPT_POST 1)
	  (if (#/^@/ data) (curl-open-input-file curl data) (_ curl CURLOPT_POSTFIELDS data))
	  (if (fc "Largefile")
	      (_ curl CURLOPT_POSTFIELDSIZE_LARGE -1)
	      (_ curl CURLOPT_POSTFIELDSIZE -1))))
      (when data-binary
	(begin
	  (_ curl CURLOPT_POST 1)
	  (if (#/^@/ data-binary) (curl-open-input-file curl data-binary) (_ curl CURLOPT_POSTFIELDS data-binary))
	  (if (fc "Largefile")
	      (_ curl CURLOPT_POSTFIELDSIZE_LARGE -1)
	      (_ curl CURLOPT_POSTFIELDSIZE -1))))
      (when data-urlencode
	  (begin
	    (_ curl CURLOPT_POST 1)
	    (cond ((#/^(.+)@(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ curl CURLOPT_POSTFIELDS
			   (string-append 
			    (m 1) "=" 
			    (uri-encode-string (port->string (open-input-file (m 2))))))))
		  ((#/^(.+)=(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ curl CURLOPT_POSTFIELDS
			   (string-append 
			    (m 1) "="
			    (uri-encode-string (m 2))))))
		  ((#/^@(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ curl CURLOPT_POSTFIELDS
			   (uri-encode-string (port->string (open-input-file (m 1)))))))
		  ((#/^=(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ curl CURLOPT_POSTFIELDS
			   (uri-encode-string (m 1)))))
		  (else  
		   (_ curl CURLOPT_POSTFIELDS (uri-encode-string data-urlencode))))
	    (if (fc "Largefile")
		(_ curl CURLOPT_POSTFIELDSIZE_LARGE -1)
		(_ curl CURLOPT_POSTFIELDSIZE -1))))
      (if ignore-content-length (_ curl CURLOPT_IGNORE_CONTENT_LENGTH 1) (_ curl CURLOPT_IGNORE_CONTENT_LENGTH 0))
      ;; cookie
      (if junk-session-cookies (_ curl CURLOPT_COOKIESESSION 0) (_ curl CURLOPT_COOKIESESSION 1))
      (if cookie 
	  (cond ((#/=/ cookie) 
		 (_ curl CURLOPT_COOKIE cookie))
		(else 
		 (_ curl CURLOPT_COOKIEFILE cookie)))
	  (begin
	    (_ curl CURLOPT_COOKIE #f)
	    (_ curl CURLOPT_COOKIEFILE #f)))
      (if cookie-jar (_ curl CURLOPT_COOKIEJAR cookie-jar) (_ curl CURLOPT_COOKIEJAR #f))
      ;; SSL
      (when (fc "SSL")
	(begin
	  (when (vc "7.19.1") (_ curl CURLOPT_CERTINFO 1))
	  (when tlsv1 (_ curl CURLOPT_SSLVERSION CURL_SSLVERSION_TLSv1))
	  (when sslv2 (_ curl CURLOPT_SSLVERSION CURL_SSLVERSION_SSLv2))
	  (when sslv3 (_ curl CURLOPT_SSLVERSION CURL_SSLVERSION_SSLv3))
	  (when cacert (_ curl CURLOPT_SSLCERT cacert))
	  (when capath (_ curl CURLOPT_CAPATH capath))
	  (when cert-type 
	    (cond ((equal? cert-type "PEM") (_ curl CURLOPT_SSLCERTTYPE cert-type))
		  ((equal? cert-type "DER") (_ curl CURLOPT_SSLCERTTYPE cert-type))
		  (else (error <curl-error> :message "SSL CERT type is invalid."))))
	  (when ciphers (_ curl CURLOPT_SSL_CIPHER_LIST ciphers))
	  (when random-file (_ curl CURLOPT_RANDOM_FILE random-file))
	  (when egd-file (_ curl CURLOPT_EGDSOCKET egd-file))
	  (when engine (_ curl CURLOPT_SSLENGINE engine))
	  (when (vc "7.16.0")
	    (begin
	      (when sessionid (_ curl CURLOPT_SSL_SESSIONID_CACHE 1))
	      (when no-sessionid (_ curl CURLOPT_SSL_SESSIONID_CACHE 0))))
	  (when cert 
	    (cond ((#/^(.+):(.+)$/ cert) 
		   => (lambda (m) 
			(begin
			  (_ curl CURLOPT_SSLKEY (m 1))
			  (_ curl CURLOPT_KEYPASSWD (m 2)))))
		  (else (_ curl CURLOPT_SSLKEY cert))))
	  (when key (_ curl CURLOPT_KEYPASSWD key))
	  (when key-type 
	    (cond ((equal? key-type "PEM") (_ curl CURLOPT_SSLKEYTYPE key-type))
		  ((equal? key-type "DER") (_ curl CURLOPT_SSLKEYTYPE key-type))
		  ((equal? key-type "ENG") (_ curl CURLOPT_SSLKEYTYPE key-type))
		  (else (error <curl-error> :message "SSL private key type is invalid."))))
	  (when pass (_ curl CURLOPT_KEYPASSWD pass))
	  (when insecure (_ curl CURLOPT_SSL_VERIFYHOST 0))))
      ;; SSH
      (when (pc "scp")
	(begin
	  (_ curl CURLOPT_SSH_AUTH_TYPES CURLSSH_AUTH_DEFAULT)
	  (when key (_ curl CURLOPT_SSH_PRIVATE_KEYFILE key))
	  (when pubkey (_ curl CURLOPT_SSH_PUBLIC_KEYFILE pubkey))
	  (when hostpubmd5 (_ curl CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 hostpubmd5))
	  (when pass (_ CURLOPT_KEYPASSWD pass))))
      ;; FTP
      (when (pc "ftp")
	(begin
	  (if ftp-port (_ curl CURLOPT_FTPPORT ftp-port) (_ curl CURLOPT_FTPPORT #f))
	  (when ftp-pasv (_ curl CURLOPT_FTPPORT #f))
	  (when quote (_ curl CURLOPT_QUOTE (list->curl-slist (string-split quote #\,))))
	  (when list-only (_ curl CURLOPT_DIRLISTONLY 1))
	  (when append (_ curl CURLOPT_APPEND 1))
	  (when use-ascii (_ curl CURLOPT_TRANSFERTEXT 1))
	  (cond ((#/^(.+)\;type\=A$/ (url-of curl)) 
		 => (lambda (m) 
		      (begin
			(_ curl CURLOPT_URL (m 1))
			(slot-set! curl 'url (m 1))
			(_ curl CURLOPT_TRANSFERTEXT 1)))))
	  (when crlf (_ curl CURLOPT_CRLF 1))
	  (when (vc "7.10.5")
	    (begin
	      (if disable-eprt (_ curl CURLOPT_FTP_USE_EPRT 0) (_ curl CURLOPT_FTP_USE_EPRT 1))
	      (if no-eprt (_ curl CURLOPT_FTP_USE_EPRT 0) (_ curl CURLOPT_FTP_USE_EPRT 1))
	      (if eprt (_ curl CURLOPT_FTP_USE_EPRT 1) (_ curl CURLOPT_FTP_USE_EPRT 0))))
	  (if disable-epsv (_ curl CURLOPT_FTP_USE_EPSV 0) (_ curl CURLOPT_FTP_USE_EPSV 1))
	  (if no-epsv (_ curl CURLOPT_FTP_USE_EPSV 0) (_ curl CURLOPT_FTP_USE_EPSV 1))
	  (if epsv (_ curl CURLOPT_FTP_USE_EPSV 1) (_ curl CURLOPT_FTP_USE_EPSV 0))
	  (when (vc "7.10.7") (when ftp-create-dirs (_ curl CURLOPT_FTP_CREATE_MISSING_DIRS 2)))
	  (when (vc "7.13.0")  (when ftp-account (_ curl CURLOPT_FTP_ACCOUNT ftp-account)))
	  (when (vc "7.14.2") (when ftp-skip-pasv-ip (_ curl CURLOPT_FTP_SKIP_PASV_IP 1)))
	  (when (vc "7.15.1")
	    (when ftp-method
	      (cond ((equal? ftp-method "multicwd") (_ curl CURLOPT_FTP_FILEMETHOD CURLFTPMETHOD_MULTICWD))
		    ((equal? ftp-method "nocwd") (_ curl CURLOPT_FTP_FILEMETHOD CURLFTPMETHOD_NOCWD))
		    ((equal? ftp-method "singlecwd") (_ curl CURLOPT_FTP_FILEMETHOD CURLFTPMETHOD_SINGLECWD))
		    (else (error <curl-error> :message "ftp method is invalid.")))))
	  (when (vc "7.15.5") (when ftp-alternative-to-user (_ curl CURLOPT_FTP_ALTERNATIVE_TO_USER ftp-alternative-to-user)))
	  (when (fc "GSS-Negotiate") (when krb (_ curl CURLOPT_KRBLEVEL krb)))
	  (when (pc "ftps")
	    (begin
	      (when ftp-ssl (_ curl CURLOPT_USE_SSL CURLUSESSL_TRY))
	      (when ftp-ssl-control (_ curl CURLOPT_USE_SSL CURLUSESSL_CONTROL))
	      (when ftp-ssl-reqd (_ curl CURLOPT_USE_SSL CURLUSESSL_ALL))
	      (when ftp-ssl-ccc (_ curl CURLOPT_FTP_SSL_CCC CURLFTPSSL_CCC_PASSIVE))
	      (when ftp-ssl-ccc-mode
		(cond ((equal? ftp-ssl-ccc-mode "active") (_ curl CURLOPT_FTP_SSL_CCC CURLFTPSSL_CCC_ACTIVE))
		      ((equal? ftp-ssl-ccc-mode "passive") (_ curl CURLOPT_FTP_SSL_CCC CURLFTPSSL_CCC_PASSIVE))
		      (else (error <curl-error> :message "ftp ssl ccc mode is invalid."))))))))
      ;; LDAP
      (when (pc "ldap")
	(when use-ascii (_ curl CURLOPT_TRANSFERTEXT) 1))
      ;; telnet
      (when (pc "telnet")
	(when telnet-option (_ curl CURLOPT_TELNETOPTIONS (list->curl-slist (string-split telnet-option #\,)))))))))

;; fflush
;;        (buffer "buffer" #f)
;;        (no-buffer "N|no-buffer" #f) 
;; CURLOPT_SOCKOPTFUNCTION, CURLOPT_SOCKOPTDATA
;;        (no-keepalive "no-keepalive" #f)
;;        (keepalive "keepalive" #f) 
;; CURLOPT_BUFFERSIZE, CURLOPT_MAX_SEND_SPEED
;;        (limit-rate "limit-rate=s" )

;; multi interface
;;        (remote-name-all "remote-name-all" #f)
;;        (globoff "g|globoff" #f)
;; may not implementaion
;;        (progress-bar "#|progress-bar" #f)
;;        (environment "environment" #f)

;;        (create-dirs "create-dirs" #f)
;;        (form-string "form-string=s" )
;;        (netrc-optional "netrc-optional" #f)
;;        (retry "retry=s" )
;;        (retry-delay "retry-delay=s" )
;;        (retry-max-time "retry-max-time=s" )
;;        (trace "trace=s" )
;;        (trace-ascii "trace-ascii=s" )
;;        (trace-time "trace-time" #f)
;;        (continue-at "C|continue-at=s" )
;;        (config "K|config=s" )
;;        (netrc "n|netrc" #f)
;;        (show-error "S|show-error" #f)
;;        (speed-limit "Y|speed-limit=s" )
;;        (speed-time "y|speed-time=s" )
;;        (q "q" #f)
;;        (silent "s|silent" #f)
;;        (write-out "w|write-out=s" )
;;        (keepalive-time "keepalive-time=i" #f)

; procedure
(define-method curl-setopt! ((curl <curl>) opt val)
  (let1 hnd (handler-of curl)
    (if hnd 
	(let1 res (curl-easy-setopt hnd opt (if (list? val) 
						(list->curl-slist val) val))
	  (slot-set! curl 'rc res)
	  (when (equal? opt CURLOPT_HTTPHEADER)
	    (unless (equal? (http-headers-of curl) val)
	      (set! (http-headers-of curl) (append (http-headers-of curl) val))))
	  (if (= res 0) #t #f))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-perform ((curl <curl>))
  (let1 hnd (handler-of curl)
    (unless (null? (http-headers-of curl))
      (curl-setopt! curl CURLOPT_HTTPHEADER (http-headers-of curl)))
    (if hnd (let1 res (curl-easy-perform hnd)
	      (slot-set! curl 'rc res)
	      (cond ((= res 0) #t)
		    (else #f)))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-strerror ((curl <curl>))
  (if (rc-of curl) 
      (curl-easy-strerror (rc-of curl))
      #f))

(define-method curl-strerror ((share <curl-share>))
  (if (rc-of share) 
      (curl-share-strerror (rc-of share))
      #f))

(define-method curl-getinfo ((curl <curl>))
  (let ((hnd (handler-of curl))
	(_ curl-easy-getinfo))
    (if hnd
	(remove not
	`(,(cons 'EFFECTIVE_URL (_ hnd CURLINFO_EFFECTIVE_URL))
	  ,(cons 'RESPONSE_CODE (_ hnd CURLINFO_RESPONSE_CODE))
	  ,(cons 'TOTAL_TIME (_ hnd CURLINFO_TOTAL_TIME))
	  ,(cons 'NAMELOOKUP_TIME (_ hnd CURLINFO_NAMELOOKUP_TIME)) 
	  ,(cons 'CONNECT_TIME (_ hnd CURLINFO_CONNECT_TIME))
	  ,(cons 'PRETRANSFER_TIME (_ hnd CURLINFO_PRETRANSFER_TIME)) 
	  ,(cons 'SIZE_UPLOAD (_ hnd CURLINFO_SIZE_UPLOAD))
	  ,(cons 'SIZE_DOWNLOAD (_ hnd CURLINFO_SIZE_DOWNLOAD)) 
	  ,(cons 'SPEED_DOWNLOAD (_ hnd CURLINFO_SPEED_DOWNLOAD)) 
	  ,(cons 'SPEED_UPLOAD (_ hnd CURLINFO_SPEED_UPLOAD))
	  ,(cons 'HEADER_SIZE (_ hnd CURLINFO_HEADER_SIZE))
	  ,(cons 'REQUEST_SIZE (_ hnd CURLINFO_REQUEST_SIZE)) 
	  ,(cons 'CONTENT_LENGTH_UPLOAD (_ hnd CURLINFO_CONTENT_LENGTH_UPLOAD))
	  ,(cons 'STARTTRANSFER_TIME (_ hnd CURLINFO_STARTTRANSFER_TIME))
	  ,(cons 'CONTENT_TYPE (_ hnd CURLINFO_CONTENT_TYPE))
	  ,(cons 'CONTENT_LENGTH_DOWNLOAD (_ hnd CURLINFO_CONTENT_LENGTH_DOWNLOAD))
	  ,(cons 'HTTP_CONNECTCODE (_ hnd CURLINFO_HTTP_CONNECTCODE))
	  ,(if (fc "SSL") (cons 'SSL_VERIFYRESULT (_ hnd CURLINFO_SSL_VERIFYRESULT)) #f)
	  ,(if (vc "7.5") (cons 'FILETIME (_ hnd CURLINFO_FILETIME)) #f)
	  ,(if (vc "7.9.7") (cons 'REDIRECT_TIME (_ hnd CURLINFO_REDIRECT_TIME)) #f)
	  ,(if (vc "7.9.7") (cons 'REDIRECT_COUNT (_ hnd CURLINFO_REDIRECT_COUNT)) #f)
	  ,(if (vc "7.10.8") (cons 'HTTPAUTH_AVAIL (_ hnd CURLINFO_HTTPAUTH_AVAIL)) #f)
	  ,(if (vc "7.10.8") (cons 'PROXYAUTH_AVAIL (_ hnd CURLINFO_PROXYAUTH_AVAIL)) #f)
	  ,(if (vc "7.12.2") (cons 'OS_ERRNO (_ hnd CURLINFO_OS_ERRNO)) #f)
	  ,(if (vc "7.12.2") (cons 'NUM_CONNECTS (_ hnd CURLINFO_NUM_CONNECTS)) #f)
	  ,(if (and (vc "7.13.3") (fc "SSL")) (cons 'SSL_ENGINES (_ hnd CURLINFO_SSL_ENGINES)) #f)
	  ,(if (vc "7.14.1") (cons 'COOKIELIST (_ hnd CURLINFO_COOKIELIST)) #f)
	  ,(if (vc "7.15.2") (cons 'LATSOCKET (_ hnd CURLINFO_LASTSOCKET)) #f)
	  ,(if (and (vc "7.15.4") (sc "ftp" (url-of curl))) (cons 'FTP_ENTRY_PATH (_ hnd CURLINFO_FTP_ENTRY_PATH)) #f)
	  ,(if (vc "7.18.2") (cons 'REDIRECT_URL (_ hnd CURLINFO_REDIRECT_URL)) #f)
	  ,(if (vc "7.19.0") (cons 'PRIMARY_IP (_ hnd CURLINFO_PRIMARY_IP)) #f)
	  ,(if (vc "7.19.0") (cons 'APPCONNECT_TIME (_ hnd CURLINFO_APPCONNECT_TIME)) #f)
	  ,(if (and (vc "7.19.1") (fc "SSL")) (cons 'CERTINFO (_ hnd CURLINFO_CERTINFO)) #f)
	  ,(if (vc "7.19.4") (cons 'CONDITION_UNMET (_ hnd CURLINFO_CONDITION_UNMET)) #f)))
    (error <curl-error> :message "curl handler is invalid."))))

(define-method curl-cleanup! ((curl <curl>))
  (let1 hnd (handler-of curl)
    (if hnd
	(let1 res (curl-easy-cleanup hnd)
	  (cond ((undefined? res)
		 (slot-set! curl 'handler #f)
		 (slot-set! curl 'url "")
		 (slot-set! curl 'http-headers '())
		 (slot-set! curl 'rc #f)
		 #t)
		(else #f)))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-reset! ((curl <curl>))
  (let1 hnd (handler-of curl)
    (if hnd
	(let1 res (curl-easy-reset hnd)
	  (cond ((undefined? res)
		 (curl-setopt! curl CURLOPT_URL (url-of curl))
		 (slot-set! curl 'rc #f)
		 #t)
		(else #f)))
	(error <curl-error> :message "curl handler is invalid."))))


; I/O
(define-method curl-open-output-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-file hnd CURLOPT_WRITEDATA filename)
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-open-input-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(begin 
	  (curl-open-file hnd CURLOPT_READDATA filename)
	  (curl-setopt! curl CURLOPT_POSTFIELDS #f)
	  (if (fc "Largefile")
	      (curl-setopt! curl CURLOPT_POSTFIELDSIZE_LARGE -1)
	      (curl-setopt! curl CURLOPT_POSTFIELDSIZE -1)))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-open-header-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-file hnd CURLOPT_WRITEHEADER filename)
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-open-error-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-file hnd CURLOPT_STDERR filename)
	(error <curl-error> :message "curl handler is invalid."))))
	 
(define-method curl-open-output-port ((curl <curl>) . out)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-port hnd CURLOPT_WRITEDATA 
			(if (null? out)
			    (open-output-string)
			    (if (output-port? (car out)) (car out)
				(error <curl-error> :message "Set output port."))))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-open-input-port ((curl <curl>) in)
  (let1 hnd (handler-of curl)
    (if hnd
	(begin
	  (curl-open-port hnd CURLOPT_READDATA
			  (if (input-port? in) in
			      (else (error <curl-error> :message "Set input port."))))
	  (curl-setopt! curl CURLOPT_POSTFIELDS #f)
	  (when (eq? in (standard-input-port)) 
	    (slot-set! curl 'http-headers (append (http-headers-of curl) '("Transfer-Encoding: chunked")))))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-open-header-port ((curl <curl>) . out)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-port hnd CURLOPT_WRITEHEADER
			(if (null? out)
			    (open-output-string)
			    (if (output-port? (car out)) (car out)
				(error <curl-error> :message "Set output port."))))
	(error <curl-error> :message "curl handler is invalid."))))

(define (curl-headers->alist headers-str . num)
  (let1 ls (remove null? (map (lambda  (h) (rfc822-read-headers (open-input-string h)))
			      (string-split headers-str "\r\n\r\n")))
    (if (null? num) ls
	(let1 n (car num)
	  (if (>= n 0) (list-ref ls n)
	      (list-ref ls (- (length ls) 1)))))))


; wrapper procedure
;; Common
(define (http-common method hostname path body . opts)
  (let-keywords opts ((no-redirect :no-redirect #f)
		      (sink :sink #f)
		      (flusher :flusher #f)
		      (ssl :ssl #f)
		      (verbose :verbose #f)
		      . opt)
		(let* ((curl (make <curl> :url (string-append (if ssl "https://" "http://") hostname path)))
		       (output (if (not sink) (curl-open-output-port curl)
				   (curl-open-output-port curl sink)))
		       (header (curl-open-header-port curl)))
		  (when verbose (curl-setopt! curl CURLOPT_VERBOSE 1))
		  (if (equal? method 'HEAD) (curl-setopt! curl CURLOPT_NOBODY 1)
		      (curl-setopt! curl CURLOPT_CUSTOMREQUEST (symbol->string method)))
		  (curl-setopt! curl CURLOPT_USERAGENT (string-append "Gauche/" (gauche-version) " " (curl-version)))
		  (curl-setopt! curl CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_NONE)
		  (when body (curl-setopt! curl CURLOPT_POSTFIELDS body))
		  (if no-redirect (curl-setopt! curl CURLOPT_FOLLOWLOCATION 0)
		      (curl-setopt! curl CURLOPT_FOLLOWLOCATION 1))
		  (unless (null? opt) 
		    (curl-setopt! curl CURLOPT_HTTPHEADER
				  (map (lambda (h) (string-append (keyword->string (car h)) ": " (cadr h))) (slices opt 2))))
		  (if (curl)
		      (if flusher (flusher output header)
			  (values
			   (number->string (cdr (assq 'RESPONSE_CODE (curl-getinfo curl))))
			   (curl-headers->alist (get-output-string header) -1)
			   (get-output-string output)))
		      #f))))

;; GET
(define (http-get hostname path . opt)
  (apply http-common 'GET hostname path #f opt))

;; HEAD
(define (http-head hostname path . opt)
  (apply http-common 'HEAD hostname path #f opt))

;; POST
(define (http-post hostname path body . opt)
  (apply http-common 'POST hostname path body opt))

;; PUT
(define (http-put hostname path body . opt)
  (apply http-common 'PUT hostname path body opt))

;; DELETE
(define (http-delete hostname path . opt)
  (apply http-common 'DELETE hostname path #f opt))

;; Epilogue
(provide "curl")

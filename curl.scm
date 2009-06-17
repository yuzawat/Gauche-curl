;;; -*- coding: utf-8; mode: scheme -*-
;;;
;;; libcurl binding for gauche
;;;
;;;  libcurl: <http://curl.haxx.se/libcurl/>

;;;
;;; Example
;;;
;;; (let* ((c (make <curl> :url "http://example.tld/test/" :options "-L"))
;;;        (output-str-port (curl-open-output-port c))
;;;        (header-str-port (curl-open-header-port c)))
;;;   (c)
;;;   (values  
;;;    (cdr (assq 'RESPONSE_CODE (curl-getinfo c)))
;;;    (get-output-string header-str-port)
;;;    (get-output-string output-str-port)))

(define-module curl
  (use gauche.mop.singleton)
  (use gauche.parseopt)
  (use gauche.parameter)
  (use gauche.version)
  (use rfc.822)
  (use rfc.uri)
  (use srfi-1)
  (use util.list)
  (export 
   <curl>
   <curl-share>
   <cuel-multi>
   <curl-base>
   <curl-multi-base>
   <curl-share-base>
   <curl-slist>

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
   curl-set-http-header!

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

   CURLOPTTYPE_OFF_T

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

   )
  )
(select-module curl)

;; Loads extension
(dynamic-load "curl")

;; global init
(curl-global-init CURL_GLOBAL_ALL)
(define curl-share-enable #t)

;; curl class
(define-class <curl-meta> ()
  ((handler :allocation :instance
	    :accessor handler-of)
   (code :allocation :instance
	 :accessor code-of
	 :init-value #f)))

(define-class <curl> (<curl-meta>)
  ((url :allocation :instance
	:init-keyword :url
	:accessor url-of)
   (options :allocation :instance
	   :init-keyword :options
	   :init-value ""
	   :accessor options-of)))

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
	 (url "url=s" #f)
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
	 (max-time "m|max-time=i" #f))
      ;; common
      (when url (begin (_ curl CURLOPT_URL url) (slot-set! curl 'url url)))
      (when curl-share-enable (_ curl CURLOPT_SHARE (handler-of (make <curl-share>))))
      (if connect-timeout (_ curl CURLOPT_CONNECTTIMEOUT connect-timeout) (_ curl CURLOPT_CONNECTTIMEOUT 0))
      (if max-time (_ curl CURLOPT_TIMEOUT max-time) (_ curl CURLOPT_TIMEOUT 0))
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
	    (cond ((#/(^.+)\;auto$/ referer) => (lambda (m) (unless (= (string-length (m 1)) 0) (_ curl CURLOPT_REFERER (m 1)))))))
	  (_ curl CURLOPT_REFERER #f))
      (when compressed (_ curl CURLOPT_ENCODING ""))
      (if fail (_ curl CURLOPT_FAILONERROR 1) (_ curl CURLOPT_FAILONERROR 0))
      (when get (_ curl CURLOPT_HTTPGET 1))
      (when header (_ curl CURLOPT_HTTPHEADER (list->curl_slist (string-split header #\,))))
      (if head (_ curl CURLOPT_NOBODY 1) (_ curl CURLOPT_NOBODY 0))
      (when post301 (_ curl CURLOPT_POSTREDIR CURL_REDIR_POST_301))
      (when post302 (_ curl CURLOPT_POSTREDIR CURL_REDIR_POST_302))
      ;; output
      (if output (curl-open-output-file curl output) (curl-open-port hnd CURLOPT_WRITEDATA (current-output-port)))
      (when remote-name (curl-open-output-file curl
					       (let1 fn (sys-basename (values-ref (uri-parse (url-of curl)) 4))
						 (if (equal? fn "") "index.html" fn))))
      (if remote-time (_ curl CURLOPT_FILETIME 1) (_ curl CURLOPT_FILETIME 0))
      (when dump-header (curl-open-header-file curl dump-header))
      (when max-filesize (_ curl CURLOPT_MAXFILESIZE_LARGE max-filesize))
      (if include (_ curl CURLOPT_HEADER 1) (_ curl CURLOPT_HEADER 0))
      (if interface (_ curl CURLOPT_INTERFACE interface) (_ curl CURLOPT_INTERFACE #f))
      (if tcp-nodelay (_ curl CURLOPT_TCP_NODELAY 1) (_ curl CURLOPT_TCP_NODELAY 0))
      ;; auth
      (if user (_ curl CURLOPT_USERPWD user) (_ curl CURLOPT_USERPWD #f))
      (when basic (_ curl CURLOPT_HTTPAUTH CURLAUTH_BASIC))
      (when digest (_ curl CURLOPT_HTTPAUTH CURLAUTH_DIGEST))
      (when negotiate (_ curl CURLOPT_HTTPAUTH CURLAUTH_GSSNEGOTIATE))
      (when ntlm (_ curl CURLOPT_HTTPAUTH CURLAUTH_NTLM))
      (when anyauth (_ curl CURLOPT_HTTPAUTH CURLAUTH_ANY))
      ;; proxy
      (if proxy (_ curl CURLOPT_PROXY proxy) (_ curl CURLOPT_PROXY #f))
      (when (vc "7.19.4")(if noproxy (_ curl CURLOPT_NOPROXY noproxy) (_ curl CURLOPT_NOPROXY #f)))
      (if proxy-user (_ curl CURLOPT_PROXYUSERPWD proxy-user) (_ curl CURLOPT_PROXYUSERPWD #f))
      (when proxy-anyauth (_ curl CURLOPT_PROXYAUTH CURLAUTH_ANY))
      (when proxy-basic (_ curl CURLOPT_PROXYAUTH CURLAUTH_BASIC))
      (when proxy-digest (_ curl CURLOPT_PROXYAUTH CURLAUTH_DIGEST))
      (when proxy-negotiate (_ curl CURLOPT_PROXYAUTH CURLAUTH_GSSNEGOTIATE))
      (when proxy-ntlm (_ curl CURLOPT_PROXYAUTH CURLAUTH_NTLM))
      ;; data upload
      (when upload-file 
	(begin
	  (_ curl CURLOPT_UPLOAD 1)
	  (curl-open-input-file curl upload-file)
	  (_ curl CURLOPT_INFILESIZE_LARGE (slot-ref (sys-stat upload-file) 'size))
	  (when (#/^http/ (url-of curl))
	    (let1 purl (string-append  
			(url-of curl) (if (#/\/$/ (url-of curl)) "" "/") (uri-encode-string upload-file))
	      (_ curl CURLOPT_URL purl)
	      (slot-set! curl 'url url)))))
      (if data
	(begin
	  (_ curl CURLOPT_POST 1)
	  (if (#/^@/ data) (curl-open-input-file curl data) (_ curl CURLOPT_POSTFIELDS data))
	  (_ curl CURLOPT_POSTFIELDSIZE_LARGE -1))
	(_ curl CURLOPT_POST 0))
      (if data-binary
	(begin
	  (_ curl CURLOPT_POST 1)
	  (if (#/^@/ data) (curl-open-input-file curl data) (_ curl CURLOPT_POSTFIELDS data))
	  (_ curl CURLOPT_POSTFIELDSIZE_LARGE -1))
	(_ curl CURLOPT_POST 0))
      (if data-urlencode
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
	    (_ curl CURLOPT_POSTFIELDSIZE_LARGE -1))
	(_ curl CURLOPT_POST 0))
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
      (if cookie-jar (_ curl CURLOPT_COOKIEJAR cookie-jar) (_ curl CURLOPT_COOKIEJAR #f)))))

;(_ curl CURLOPT_HTTPAUTH CURLAUTH_ANYSAFE)
;(_ curl CURLOPT_HTTPAUTH CURLAUTH_DIGEST_IE)

;;        (progress-bar "#|progress-bar" #f)
;;        (buffer "buffer" #f)
;;        (cacert "cacert=s")
;;        (capath "capath=s")
;;        (cert-type "cert-type=s") 
;;        (ciphers "ciphers=s")
;;        (create-dirs "create-dirs" #f)
;;        (crlf "crlf" #f)
;;        (disable-eprt "disable-eprt" #f)
;;        (disable-epsv "disable-epsv" #f)
;;        (egd-file "egd-file=s" )
;;        (engine "engine=s" )
;;        (environment "environment" #f)
;;        (eprt "eprt" #f)
;;        (epsv "epsv" #f)
;;        (form-string "form-string=s" )
;;        (ftp-account "ftp-account=s" )
;;        (ftp-alternative-to-user "ftp-alternative-to-user=s" )
;;        (ftp-create-dirs "ftp-create-dirs" #f)
;;        (ftp-method "ftp-method=s" )
;;        (ftp-pasv "ftp-pasv" #f)
;;        (ftp-skip-pasv-ip "ftp-skip-pasv-ip" #f)
;;        (ftp-ssl "ftp-ssl" #f)
;;        (ftp-ssl-ccc "ftp-ssl-ccc" #f)
;;        (ftp-ssl-ccc-mode "ftp-ssl-ccc-mode=s" )
;;        (ftp-ssl-control "ftp-ssl-control" #f)
;;        (ftp-ssl-reqd "ftp-ssl-reqd" #f)
;;        (hostpubmd5 "hostpubmd5=s" )
;;        (keepalive "keepalive" #f)
;;        (key "key=s" )
;;        (key-type "key-type=s" )
;;        (krb "krb=s" )
;;        (limit-rate "limit-rate=s" )
;;        (local-port "local-port=s" )
;;        (netrc-optional "netrc-optional" #f)
;;        (no-eprt "no-eprt" #f)
;;        (no-epsv "no-epsv" #f)
;;        (no-keepalive "no-keepalive" #f)
;;        (no-sessionid "no-sessionid" #f)
;;        (pass "pass=s" )
;;        (pubkey "pubkey=s" )
;;        (random-file "random-file=s" )
;;        (raw "raw" #f)
;;        (remote-name-all "remote-name-all" #f)
;;        (retry "retry=s" )
;;        (retry-delay "retry-delay=s" )
;;        (retry-max-time "retry-max-time=s" )
;;        (sessionid "sessionid" #f)
;;        (socks4 "socks4=s" )
;;        (socks4a "socks4a=s" )
;;        (socks5 "socks5=s" )
;;        (socks5-gssapi-nec "socks5-gssapi-nec" #f)
;;        (socks5-gssapi-service "socks5-gssapi-service=s" )
;;        (socks5-hostname "socks5-hostname=s" )
;;        (trace "trace=s" )
;;        (trace-ascii "trace-ascii=s" )
;;        (trace-time "trace-time" #f)
;;        (http1.0 "0|http1.0" #f)
;;        (tlsv1 "1|tlsv1" #f)
;;        (sslv2 "2|sslv2" #f)
;;        (sslv3 "3|sslv3" #f)
;;        (ipv4 "4|ipv4" #f)
;;        (ipv6 "6|ipv6" #f)
;;        (use-ascii "B|use-ascii" #f)
;;        (continue-at "C|continue-at=s" )
;;        (cert "E|cert=s" )
;;        (form "F|form=s" )
;;        (config "K|config=s" )
;;        (no-buffer "N|no-buffer" #f)
;;        (ftp-port "P|ftp-port=s" )
;;        (quote "Q|quote=s" )
;;        (show-error "S|show-error" #f)
;;        (speed-limit "Y|speed-limit=s" )
;;        (append "a|append" #f)
;;        (globoff "g|globoff" #f)
;;        (insecure "k|insecure" #f)
;;        (list-only "l|list-only" #f)
;;        (netrc "n|netrc" #f)
;;        (proxytunnel "p|proxytunnel" #f)
;;        (q "q" #f)
;;        (range "r|range=s" )
;;        (silent "s|silent" #f)
;;        (telnet-option "t|telnet-option=s" )
;;        (write-out "w|write-out=s" )
;;        (speed-time "y|speed-time=s" )
;;        (time-cond "z|time-cond=s"))
;;        (keepalive-time "keepalive-time=i" #f)

; procedure
(define-method curl-setopt! ((curl <curl>) opt val)
  (let1 hnd (handler-of curl)
    (if hnd (let1 res (curl-easy-setopt hnd opt val)
	      (slot-set! curl 'code res)
	      (if (= res 0) #t #f))
	(error "curl handler is invalid."))))

(define-method curl-perform ((curl <curl>))
  (let1 hnd (handler-of curl)
    (if hnd (let1 res (curl-easy-perform hnd)
	      (slot-set! curl 'code res)
	      (cond ((= res 0) #t)
		    (else #f)))
	(error "curl handler is invalid."))))

(define-method curl-strerror ((curl <curl>))
  (if (code-of curl) 
      (curl-easy-strerror (code-of curl))
      #f))

(define-method curl-strerror ((share <curl-share>))
  (if (code-of share) 
      (curl-share-strerror (code-of share))
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
	  ,(if (vc "7.15.2") (cons 'LASTSOCKET (_ hnd CURLINFO_LASTSOCKET)) #f)
	  ,(if (and (vc "7.15.4") (sc "ftp" (url-of curl))) (cons 'FTP_ENTRY_PATH (_ hnd CURLINFO_FTP_ENTRY_PATH)) #f)
	  ,(if (vc "7.18.2") (cons 'REDIRECT_URL (_ hnd CURLINFO_REDIRECT_URL)) #f)
	  ,(if (vc "7.19.0") (cons 'PRIMARY_IP (_ hnd CURLINFO_PRIMARY_IP)) #f)
	  ,(if (vc "7.19.0") (cons 'APPCONNECT_TIME (_ hnd CURLINFO_APPCONNECT_TIME)) #f)
	  ,(if (vc "7.19.1") (cons 'CERTINFO (_ hnd CURLINFO_CERTINFO)) #f)
	  ,(if (vc "7.19.4") (cons 'CONDITION_UNMET (_ hnd CURLINFO_CONDITION_UNMET)) #f)))
    (error "curl handler is invalid."))))

(define-method curl-cleanup! ((curl <curl>))
  (let1 hnd (handler-of curl)
    (if hnd
	(let1 res (curl-easy-cleanup hnd)
	  (cond ((undefined? res)
		 (slot-set! curl 'handler #f)
		 (slot-set! curl 'url "")
		 (slot-set! curl 'code #f)
		 #t)
		(else #f)))
	(error "curl handler is invalid."))))

(define-method curl-reset! ((curl <curl>))
  (let1 hnd (handler-of curl)
    (if hnd
	(let1 res (curl-easy-reset hnd)
	  (cond ((undefined? res)
		 (curl-setopt! curl CURLOPT_URL (url-of curl))
		 (slot-set! curl 'code #f)
		 #t)
		(else #f)))
	(error "curl handler is invalid."))))

(define-method curl-set-http-header! ((curl <curl>) ls)
  (curl-setopt! curl CURLOPT_HTTPHEADER (list->curl-slist ls)))

; I/O
(define-method curl-open-output-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-file hnd CURLOPT_WRITEDATA filename)
	(error "curl handler is invalid."))))

(define-method curl-open-input-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-file hnd CURLOPT_READDATA filename)
	(error "curl handler is invalid."))))

(define-method curl-open-header-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-file hnd CURLOPT_WRITEHEADER filename)
	(error "curl handler is invalid."))))

(define-method curl-open-error-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-file hnd CURLOPT_STDERR filename)
	(error "curl handler is invalid."))))
	 
(define-method curl-open-output-port ((curl <curl>) . out)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-port hnd CURLOPT_WRITEDATA 
			(if (null? out)
			    (open-output-string)
			    (if (output-port? (car out)) (car out)
				(error "Set output port."))))
	(error "curl handler is invalid."))))

(define-method curl-open-input-port ((curl <curl>) in)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-port hnd CURLOPT_READDATA
			(if (input-port? in) in
			    (else (error "Set input port."))))
	(error "curl handler is invalid."))))

(define-method curl-open-header-port ((curl <curl>) . out)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-port hnd CURLOPT_WRITEHEADER
			(if (null? out)
			    (open-output-string)
			    (if (output-port? (car out)) (car out)
				(error "Set output port."))))
	(error "curl handler is invalid."))))

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
		      ;(sink :sink (open-output-string))
		      ;(flusher :flusher (lambda (sink _) (get-output-string sink)))
		      (ssl :ssl #f)
		      (verbose :verbose #f)
		      . opt)
		(let* ((curl (make <curl> :url (string-append (if ssl "https://" "http://") hostname path)))
		       (output (curl-open-output-port curl))
		       (header (curl-open-header-port curl)))
		  (when verbose (curl-setopt! curl CURLOPT_VERBOSE 1))
		  (if (equal? method 'HEAD) (curl-setopt! curl CURLOPT_NOBODY 1)
		      (curl-setopt! curl CURLOPT_CUSTOMREQUEST (symbol->string method)))
		  (curl-setopt! curl CURLOPT_USERAGENT (string-append "Gauche/" (gauche-version) " " (curl-version)))
		  (curl-setopt! curl CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_NONE)
		  (when body (curl-setopt! curl CURLOPT_POSTFIELDS body))
		  (if no-redirect (curl-setopt! curl CURLOPT_FOLLOWLOCATION 0)
		      (curl-setopt! curl CURLOPT_FOLLOWLOCATION 1))
		  (unless (null? opt) (curl-set-http-header! 
				       curl 
				       (map (lambda (h) (string-append (keyword->string (car h)) ": " (cadr h))) (slices opt 2))))
		  (if (curl)
		      (values
		       (cdr (assq 'RESPONSE_CODE (curl-getinfo curl)))
		       (curl-headers->alist (get-output-string header) -1)
		       (get-output-string output))
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

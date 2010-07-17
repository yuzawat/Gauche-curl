;;; -*- coding: utf-8; mode: scheme -*-
;;;
;;; libcurl binding for gauche
;;;  libcurl version 7.21.0: <http://curl.haxx.se/libcurl/>
;;;
;;; Last Updated: "2010/07/17 13:22.40"
;;;
;;;  Copyright (c) 2010  yuzawat <suzdalenator@gmail.com>


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
  (use file.util)
  (use gauche.mop.singleton)
  (use gauche.parseopt)
  (use gauche.threads)
  (use gauche.version)
  (use rfc.822)
  (use rfc.uri)
  (use srfi-1)
  (use srfi-13)
  (use util.list)
  (use util.match)
  (export 
   <curl>
   <curl-multi>
   <curl-share>
   <curl-base>
   <curl-multi-base>
   <curl-error>
   <curl-progress>

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
   curl-easy-pause
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
   curl-multi-setopt
   curl-multi-perform
   curl-multi-fdset
   curl-multi-strerror
   curl-multi-timeout
   curl-multi-info-read

   curl-share-init
   curl-share-setopt
   curl-share-strerror

   curl-version
   curl-version-info

   curl-open-file
   curl-open-port
   curl-close-file

   curl-list->curl-slist
   curl-slist->list

   curl-set-progress-options
   curl-get-progress-numbers

   curl-set-socket-options

   ;; procedure
   curl-setopt!
   curl-perform
   curl-getinfo
   curl-cleanup!
   curl-reset!
   curl-strerror
   curl-pause
   curl-unpause

   curl-handler-add!
   curl-handler-remove!
   curl-timeout!
   curl-fdset
   curl-multi-info->list
   curl-async-perform

   curl-open-output-file
   curl-open-input-file
   curl-open-header-file
   curl-open-error-file
   curl-open-output-port
   curl-open-input-port
   curl-open-header-port
   curl-headers->alist

   curl-parse-form-opt-string
   curl-set-http-form!

   curl-set-progress!
   curl-get-progress

   handler-of
   handlers-of
   rc-of
   remains-of
   url-of
   options-of

   http-get
   http-head
   http-post
   http-put
   http-delete

   http-compose-query
   http-compose-form-data
   http-user-agent

   ;; curl response code
   CURLE_OK
   CURLE_UNSUPPORTED_PROTOCOL
   CURLE_FAILED_INIT
   CURLE_URL_MALFORMAT
   CURLE_COULDNT_RESOLVE_PROXY
   CURLE_COULDNT_RESOLVE_HOST
   CURLE_COULDNT_CONNECT
   CURLE_FTP_WEIRD_SERVER_REPLY
   CURLE_FTP_ACCESS_DENIED
   CURLE_REMOTE_ACCESS_DENIED
   CURLE_FTP_WEIRD_PASS_REPLY
   CURLE_FTP_WEIRD_PASV_REPLY
   CURLE_FTP_WEIRD_227_FORMAT
   CURLE_FTP_CANT_GET_HOST
   CURLE_FTP_COULDNT_SET_BINARY
   CURLE_FTP_COULDNT_SET_TYPE
   CURLE_PARTIAL_FILE
   CURLE_FTP_COULDNT_RETR_FILE
   CURLE_FTP_QUOTE_ERROR
   CURLE_QUOTE_ERROR
   CURLE_HTTP_RETURNED_ERROR
   CURLE_WRITE_ERROR
   CURLE_UPLOAD_FAILED
   CURLE_READ_ERROR
   CURLE_OUT_OF_MEMORY
   CURLE_OPERATION_TIMEDOUT
   CURLE_FTP_PORT_FAILED
   CURLE_FTP_COULDNT_USE_REST
   CURLE_HTTP_RANGE_ERROR
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
   CURLE_TFTP_DISKFULL
   CURLE_REMOTE_DISK_FULL
   CURLE_TFTP_ILLEGAL
   CURLE_TFTP_UNKNOWNID
   CURLE_TFTP_EXISTS
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
   CURLOPT_SSLCERTPASSWD
   CURLOPT_SSLKEYPASSWD
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
   CURLOPT_FTPLISTONLY
   CURLOPT_FTPAPPEND
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
   CURLOPT_KRB4LEVEL
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
   CURLOPT_FTP_SSL
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
   CURLOPT_POST301
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
   CURLOPT_SSH_KNOWNHOSTS
   CURLOPT_SSH_KEYFUNCTION
   CURLOPT_SSH_KEYDATA
   CURLOPT_RTSP_REQUEST
   CURLOPT_RTSP_SESSION_ID
   CURLOPT_RTSP_STREAM_URI
   CURLOPT_RTSP_TRANSPORT
   #;CURLOPT_RTSP_HEADER
   CURLOPT_RTSP_CLIENT_CSEQ
   CURLOPT_RTSP_SERVER_CSEQ
   CURLOPT_INTERLEAVEFUNCTION
   CURLOPT_INTERLEAVEDATA
   CURLOPT_MAIL_FROM
   CURLOPT_MAIL_RCPT
   CURLOPT_FTP_USE_PRET

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
   CURLINFO_PRIMARY_PORT
   CURLINFO_LOCAL_IP
   CURLINFO_LOCAL_PORT
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
   CURLFTPSSL_NONE
   CURLFTPSSL_TRY
   CURLFTPSSL_CONTROL
   CURLFTPSSL_ALL
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

   ;; curl socktype
   CURLSOCKTYPE_IPCXN

   ;; RTSP enum values
   CURL_RTSPREQ_OPTIONS
   CURL_RTSPREQ_DESCRIBE
   CURL_RTSPREQ_ANNOUNCE
   CURL_RTSPREQ_SETUP
   CURL_RTSPREQ_PLAY
   CURL_RTSPREQ_PAUSE
   CURL_RTSPREQ_TEARDOWN
   CURL_RTSPREQ_GET_PARAMETER
   CURL_RTSPREQ_SET_PARAMETER
   CURL_RTSPREQ_RECORD
   CURL_RTSPREQ_RECEIVE

   ;; PROTO enum values
   CURLPROTO_HTTP
   CURLPROTO_HTTPS
   CURLPROTO_FTP
   CURLPROTO_FTPS
   CURLPROTO_SCP
   CURLPROTO_SFTP
   CURLPROTO_TELNET
   CURLPROTO_LDAP
   CURLPROTO_LDAPS
   CURLPROTO_DICT
   CURLPROTO_FILE
   CURLPROTO_TFTP
   CURLPROTO_IMAP
   CURLPROTO_IMAPS
   CURLPROTO_POP3
   CURLPROTO_POP3S
   CURLPROTO_SMTP
   CURLPROTO_SMTPS
   CURLPROTO_RTSP
   CURLPROTO_RTMP
   CURLPROTO_RTMPT
   CURLPROTO_RTMPE
   CURLPROTO_RTMPTE
   CURLPROTO_RTMPS
   CURLPROTO_RTMPTS
   CURLPROTO_ALL))

(select-module curl)

(autoload rfc.http 
	  http-compose-query
	  http-compose-form-data
	  http-user-agent
	  <http-error>)

;;; Loads extension
(dynamic-load "curl")


;;; global init
(curl-global-init CURL_GLOBAL_ALL)
(define curl-share-enable #t)


;;; classes
(define-class <curl-meta> ()
  ((handler :allocation :instance
	    :accessor handler-of)
   (rc :allocation :instance
       :accessor rc-of
       :init-value #f)))

;; easy interface
(define-class <curl> (<curl-meta>)
  ((url :allocation :instance
	:init-keyword :url
	:init-value ""
	:accessor url-of)
   (options :allocation :instance
	    :init-keyword :options
	    :init-value ""
	    :accessor options-of)
   (no-option :allocation :instance
	      :init-keyword :no-option
	      :init-value #f
	      :accessor no-option-of)
   (reuse :allocation :instance
	  :init-keyword :reuse
	  :init-value #t)
   (info :allocation :instance
	 :init-value #f)
   (progress :allocation :instance
	     :init-keyword :progress
	     :init-value #f
	     :accessor progress-of)
   (http-headers :allocation :instance
		 :init-value '()
		 :accessor http-headers-of)))

(define-method initialize ((curl <curl>) initargs)
  (next-method)
  (if (and (slot-bound? curl 'url) 
	   (not (equal? (slot-ref curl 'url) "")))
      (begin
	(slot-set! curl 'handler (if (and (slot-ref curl 'reuse) enthread?)
				     (let1 sought (seek-pool (url-of curl))
				       (if sought sought 
					   (curl-easy-init)))
				     (curl-easy-init)))
	(curl-setopt! curl CURLOPT_URL (url-of curl)))
      (slot-set! curl 'handler (curl-easy-init)))
  (unless (no-option-of curl)
    (when (slot-bound? curl 'options)
      (%easy-options curl (options-of curl)))))

(define-method object-apply ((curl <curl>))
  (curl-perform curl))

;; multi interface
(define-class <curl-multi> (<curl-meta>)
  ((handlers :allocation :instance
	     :init-value '()
	     :accessor handlers-of)
   (remains :allocation :instance
	    :init-value 0
	    :accessor remains-of)
   (timeout :allocation :instance
	    :init-keyword :timeout
	    :init-value 0
	    :accessor timeout-of)
   (maxconnect :allocation :instance
	       :init-keyword :maxconnect
	       :init-value 10
	       :accessor maxconnect-of)
   (pipelining :allocation :instance
	       :init-keyword :pipelining
	       :init-value #f
	       :accessor pipilining-of)))

(define-method initialize ((curlm <curl-multi>) initargs)
  (next-method)
  (slot-set! curlm 'handler (curl-multi-init))
  (and (vc "7.15.4") (not (= (timeout-of curlm) 0)) 
       (curl-multi-timeout (handler-of curlm) (timeout-of curlm)))
  (and (vc "7.16.0") (pipilining-of curlm)
       (curl-setopt! curlm CURLMOPT_PIPELINING 1))
  (and (vc "7.16.3") (not (= (maxconnect-of curlm) 10)) 
       (curl-setopt! curlm CURLMOPT_MAXCONNECTS (maxconnect-of curlm))))

(define-method object-apply ((curlm <curl-multi>))
  (curl-perform curlm))

;; share interface
(define-class <curl-share> (<curl-meta> <singleton-mixin>)
  ())

(define-method initialize ((share <curl-share>) initargs)
  (next-method)
  (slot-set! share 'handler (curl-share-init))
  (curl-setopt! share CURLSHOPT_SHARE CURL_LOCK_DATA_COOKIE)
  (curl-setopt! share CURLSHOPT_SHARE CURL_LOCK_DATA_DNS))


;;; condition
(define-condition-type <curl-error> <error> #f)


;;; utils
(define enthread?
  (not (eq? (gauche-thread-type) 'none)))

;; libcurl version check
(define (vc numstr)
  (let1 version (cdr (assoc "version" (curl-version-info)))
    (version>=? version numstr)))

;; libcurl features check
(define (fc str)
  (let1 features (cdr (assoc "features" (curl-version-info)))
    (if ((string->regexp str) features) #t #f)))

;; libcurl support protocols check
(define (pc str)
  (let1 protocols (cdr (assoc "protocols" (curl-version-info)))
    (if ((string->regexp str) protocols) #t #f)))

;; URL scheme check
(define (sc str url)
  (let1 scheme (values-ref (uri-parse url) 0)
    (if ((string->regexp str) scheme) #t #f)))

;; libssh2 version check
(define (libssh2c numstr)
  (let* ((libssh-version (assoc "libssh_version" (curl-version-info)))
         (version ((#/^.+\/(.+)$/ (cdr libssh-version)) 1)))
    (version>=? version numstr)))

;; limit rate unit parser
(define (parse-unit limit-rate)
  (let1 byte-num ((string->regexp "^(\\d+)([GgMmKkBb]?)$") limit-rate)
    (if byte-num
	(let ((num (string->number (byte-num 1)))
	      (unit (byte-num 2)))
	  (cond ((#/[Gg]/ unit) (* num 1024 1024 1024))
		((#/[Mm]/ unit) (* num 1024 1024))
		((#/[Kk]/ unit) (* num 1024))
		(else num)))
	(error <curl-error> :message "unsupported rate unit"))))

;; MIME type from suffix
(define (mime-type-db)
  (let1 mime-type-db-file "/etc/mime.types"
    (if (file-exists? mime-type-db-file)
	(let1 mime-type-table (make-hash-table 'string=?)
	  (for-each (lambda (mime-ls) (when (list? mime-ls) 
					(when (not (null? (cdr mime-ls))) 
					  (for-each (lambda (suffix) (hash-table-put! mime-type-table suffix (car mime-ls)))
						    (cdr mime-ls)))))
		    (map (lambda (mime) (if (regmatch? ((string->regexp "^#") mime)) #f (string-split mime #/\s+/)))  
			 (call-with-input-file mime-type-db-file (cut port->string-list <>))))
	  mime-type-table)
	(hash-table 'string=? '("txt" . "text/plain")
		    '("xml" . "text/xml")
		    '("htm" . "text/html")
		    '("html" . "text/html")
		    '("jpg" . "image/jpeg")
		    '("png" . "image/png")
		    '("gif" . "image/gif")))))

(define (get-content-type fn . default)
  (let ((content-types (mime-type-db))
	(default-type (if (not (null? default))
			 (car default) #f)))
    (let1 suffix (path-extension fn)
      (if suffix (hash-table-get content-types suffix default-type) 
	  default-type))))

;; This function passes a form option string to http-compose-form-data. 
;; But, it don't work completely as same as curl(1).
(define (parse-form-opt-string str . nofile)
  (define (opt-parse ls)
    (append-map (lambda (optn) 
		  (let1 v (string-split optn #\=)
		    (cond ((equal? (car v) "type") `(:content-type ,(cadr v)))
			  ((equal? (car v) "filename") `(:name ,(cadr v)))
			  ((equal? (car v) "headers") `(:name ,(cadr v)))
			  (else (error <curl-error> :message "form option argument is invalid.")))))
		ls))
  (let*((pstr ((string->regexp "^(.+?)=(.+)$") str))
	(name (pstr 1))
	(fvalue ((string->regexp "^([@<])(.+)$") (pstr 2))))
    (map (lambda (vn) (let* ((fnparts (string-split vn #\;))
			     (vname (if (and fvalue (null? nofile)) 
					((#/^[@<]?(.+)$/ (car fnparts)) 1) (car fnparts))))
			(append (if (and fvalue (null? nofile))
				    (cond ((equal? (fvalue 1) "@") 
					   (append `(,name :file: ,vname) 
						   (if (not (find (lambda (o) (if (#/^type=/ o) #t #f)) (cdr fnparts)))
						       `(:content-type ,(get-content-type vname "application/octet-stream"))
						       '())))
					  ((equal? (fvalue 1) "<") 
					   `(,name :value ,(call-with-input-file vname (cut port->string <>)))))
				    `(,name :value ,vname))
				(if (null? (cdr fnparts)) '()
				    (opt-parse (cdr fnparts))))))
	 (string-split (pstr 2) #\,))))

(define (protocol->number str)
  (let* ((protocols
          (list (cons "all" CURLPROTO_ALL)
                (cons "http" CURLPROTO_HTTP)
                (cons "https" CURLPROTO_HTTPS)
                (cons "ftp" CURLPROTO_FTP)
                (cons "ftps" CURLPROTO_FTPS)
                (cons "scp" CURLPROTO_SCP)
                (cons "sftp" CURLPROTO_SFTP)
                (cons "telnet" CURLPROTO_TELNET)
                (cons "ldap" CURLPROTO_LDAP)
                (cons "ldaps" CURLPROTO_LDAPS)
                (cons "dict" CURLPROTO_DICT)
                (cons "file" CURLPROTO_FILE)
                (cons "tftp" CURLPROTO_TFTP)
                (cons "imap" CURLPROTO_IMAP)
                (cons "imaps" CURLPROTO_IMAPS)
                (cons "pop3" CURLPROTO_POP3)
                (cons "pop3s" CURLPROTO_POP3S)
                (cons "smtp" CURLPROTO_SMTP)
                (cons "smtps" CURLPROTO_SMTPS)
                (cons "rtsp" CURLPROTO_RTSP)))
         (proto-ls (map (lambda (p)
			  (cond (((string->regexp "^([\+\-\=])?(.+)$") p) =>
				 (lambda (r)
				   (let ((action (if (r 1) (r 1) "+"))
					 (type (cdr (assoc (string-downcase (r 2)) protocols))))
				     (cons action type))))
				(else (error "protocol string format is invalid.")))) (string-split str #\,))))
    (let loop ((proto CURLPROTO_ALL)
               (proto-ls proto-ls))
      (if (null? proto-ls) proto
          (let ((action (car (car proto-ls)))
                (type (cdr (car proto-ls))))
            (loop (cond ((equal? action "=") type)
                        ((equal? action "+") (logior proto type))
                        ((equal? action "-") (logand proto (lognot type))))
                  (cdr proto-ls)))))))

(define (check-and-create-directory fn create)
  (let* ((n (sys-normalize-pathname fn :expand #t  :canonicalize #t :absolute #t))
	 (d (sys-dirname n)))
    (if (file-is-directory? d) n
	(if create (begin (make-directory* d) n)
	    (error <curl-error> (string-append d " doesn't exist."))))))


;;; connection pool
(define pool (make-hash-table 'string=?))

(define touching-pool 
  (if enthread? (make-mutex 'touching-pool) 
      #f))

(define (seek-pool url)
  (if (and enthread? (vc "7.12.1"))
      (if (eq? (mutex-state touching-pool) 'not-abandoned)
	  (begin
	    (mutex-lock! touching-pool)
	    (let* ((u (make-url-key url))
		   (c (hash-table-get pool u #f)))
	      (cond (c (hash-table-delete! pool u)
		       (mutex-unlock! touching-pool)
		       (curl-easy-reset c)
		       c)
		    (else
		     (mutex-unlock! touching-pool) 
		     #f))))
	  #f)
      #f))

(define-method put-pool ((c <curl-base>))
  (when enthread?
    (when (eq? (mutex-state touching-pool) 'not-abandoned)
      (begin
	(mutex-lock! touching-pool)
	(hash-table-put! pool (make-url-key (curl-easy-getinfo c CURLINFO_EFFECTIVE_URL)) c)
	(mutex-unlock! touching-pool)))))

(define (make-url-key url)
  (receive (scheme #f server port #f #f #f)
      (uri-parse url)
    (string-append scheme server (if port (x->string port) ""))))


;;; parse options
(define-method %easy-options ((curl <curl>) args)
  (let ((argls (if (string? args) (string-split args #/\s+/) args))
	(hnd (handler-of curl))
	(c curl)
	(_ curl-setopt!))
    (let-args argls
	((append-opt "a|append" #f)
	 (user-agent "A|user-agent=s" #f)
	 (anyauth "anyauth" #f)
	 (cookie "b|cookie=s" #f)
	 (use-ascii "B|use-ascii" #f)
	 (basic "basic" #f)
	 (ciphers "ciphers=s" #f)
	 (compressed "compressed" #f)
	 (connect-timeout "connect-timeout=i" #f)
	 (cookie-jar "c|cookie-jar=s" #f)
	 (continue-at "C|continue-at=i" #f)
	 (create-dirs "create-dirs" #f)
	 (crlf "crlf" #f)
	 (crlfile "crlfile=s" #f)
	 (data "d|data|data-ascii=s" #f)
	 (data-binary "data-binary=s" #f)
	 (data-urlencode "data-urlencode=s" #f)
	 (digest "digest" #f)
	 (disable-eprt "disable-eprt" #f)
	 (eprt "eprt" #f)
	 (no-eprt "no-eprt" #f)
	 (disable-epsv "disable-epsv" #f)
	 (epsv "epsv" #f)
	 (no-epsv "no-epsv" #f)
	 (dump-header "D|dump-header=s" #f)
	 (referer "e|referer=s" #f)
	 (engine "engine=s" #f)
	 ;; --environment (not implemented)
	 (egd-file "egd-file=s" #f)
	 (cert "E|cert=s" #f)
	 (cert-type "cert-type=s" #f) 
	 (cacert "cacert=s" #f)
	 (capath "capath=s" #f)
	 (fail "f|fail" #f)
	 (ftp-account "ftp-account=s" #f)
	 (ftp-create-dirs "ftp-create-dirs" #f)
	 (ftp-method "ftp-method=s" #f)
	 (ftp-pasv "ftp-pasv" #f)
	 (ftp-skip-pasv-ip "ftp-skip-pasv-ip" #f)
	 (ftp-alternative-to-user "ftp-alternative-to-user=s" #f)
	 (ftp-pret "ftp-pret" #f)
	 (ssl "ssl" #f)
	 (ftp-ssl "ftp-ssl" #f)
	 (ftp-ssl-control "ftp-ssl-control" #f)
	 (ssl-reqd "ssl-reqd" #f)
	 (ftp-ssl-reqd "ftp-ssl-reqd" #f)
	 (ftp-ssl-ccc "ftp-ssl-ccc" #f)
	 (ftp-ssl-ccc-mode "ftp-ssl-ccc-mode=s" #f)
	 (form "F|form=s" #f)
	 (form-string "form-string=s" #f)
	 ;; -g/globoff (not implemented)
	 (get "G|get" #f)
	 ;; --help (not implemented)
	 (header "H|header=s" #f)
	 (hostpubmd5 "hostpubmd5=s" #f)
	 (ignore-content-length "ignore-content-length" #f)
	 (include "i|include" #f)
	 (interface "interface=s" #f)
	 (head "I|head" #f)
	 (junk-session-cookies "j|junk-session-cookies" #f)
	 (insecure "k|insecure" #f)
	 (keepalive-time "keepalive-time=i" #f)
	 (key "key=s" #f)
	 (key-type "key-type=s" #f)
	 (krb "krb=s" #f)
	 ;; -K/--config (not implemented)
	 ;; --libcurl (not implemented)
	 (limit-rate "limit-rate=s" #f)
	 (list-only "l|list-only" #f)
	 (local-port "local-port=s" #f)
	 (location "L|location" #f)
	 (location-trusted "location-trusted" #f)
	 (mail-rcpt "mail-rcpt=s" #f)
	 (mail-from "mail-from=s" #f)
	 (max-filesize "max-filesize=i" #f)
	 (max-time "m|max-time=i" #f)
	 ;; -M/--manual (not implemented)
	 ;; -n/--netrc (not implemented)
	 ;; --netrc-optional (not implemented)
	 (negotiate "negotiate" #f)
	 ;; -N/--no-buffer (not implemented)
	 (no-keepalive "no-keepalive" #f)
	 (keepalive "keepalive" #f)
	 (no-sessionid "no-sessionid" #f)
	 (sessionid "sessionid" #f)
	 (noproxy "noproxy=s" #f)
	 (ntlm "ntlm" #f)
	 (output "o|output=s" #f)
	 (remote-name "O|remote-name" #f)
	 ;; --remote-name-all (not implemented)
	 (pass "pass=s" #f)
	 (post301 "post301" #f)
	 (post302 "post302" #f)
	 (proto "proto=s" #f)
	 (proto-redir "proto-redir=s" #f)
	 (proxy-anyauth "proxy-anyauth" #f)
	 (proxy-basic "proxy-basic" #f)
	 (proxy-digest "proxy-digest" #f)
	 (proxy-negotiate "proxy-negotiate" #f)
	 (proxy-ntlm "proxy-ntlm" #f)
	 (proxy1.0 "proxy1_0=s" #f)
	 (proxytunnel "p|proxytunnel" #f)
	 (pubkey "pubkey=s" #f)
	 (ftp-port "P|ftp-port=s" #f)
	 ;; -q (not implemented)
	 (quote-opt "Q|quote=s" #f)
	 (random-file "random-file=s" #f)
	 (range "r|range=s" #f)
	 (raw "raw" #f)
	 (remote-time "R|remote-time=s" #f)
	 ;; --retry (not implemented)
	 ;; --retry-delay (not implemented)
	 ;; --retry-max-time (not implemented)
	 ;; -s/--silent (not implemented)
	 ;; -S/--show-error (not implemented)
	 (socks4 "socks4=s" #f)
	 (socks4a "socks4a=s" #f)
	 (socks5-hostname "socks5-hostname=s" #f)
	 (socks5 "socks5=s" #f)
	 (socks5-gssapi-service "socks5-gssapi-service=s" #f)
	 (socks5-gssapi-nec "socks5-gssapi-nec" #f)
	 (stderr "stderr=s" #f)
	 (tcp-nodelay "tcp-nodelay" #f)
	 (telnet-option "t|telnet-option=s" #f)
	 (tftp-blksize "tftp-blksize=i" 512)
	 (upload-file "T|upload-file=s" #f)
	 ;; --trace (not implemented)
	 ;; --trace-ascii (not implemented)
	 ;; --trace-time (not implemented)
	 (user "u|user=s" #f)
	 (proxy-user "U|proxy-user=s" #f)
	 (urlstr "url=s" #f)
	 (verbose "v|verbose" #f)
	 ;; -V/--version (not implemented)
	 ;; -w/--write-out (not implemented)
	 (proxy "x|proxy=s" #f)
	 (request "X|request=s" #f)
	 (speed-limit "Y|speed-limit=i" #f)
	 (speed-time "y|speed-time=i" #f)
	 (time-cond "z|time-cond=s" #f)
	 (max-redirs "max-redirs=i" #f)
	 (http1.0 "0|http1_0" #f)
	 (tlsv1 "1|tlsv1" #f)
	 (sslv2 "2|sslv2" #f)
	 (sslv3 "3|sslv3" #f)
	 (ipv4 "4|ipv4" #f)
	 (ipv6 "6|ipv6" #f)
	 (progress-bar "progress-bar" #f))
      ;; common
      (when urlstr (begin (_ c CURLOPT_URL urlstr) (set! (url-of c) urlstr)))
      (when curl-share-enable (_ c CURLOPT_SHARE (handler-of (make <curl-share>))))
      (if connect-timeout (_ c CURLOPT_CONNECTTIMEOUT connect-timeout) (_ c CURLOPT_CONNECTTIMEOUT 0))
      (if max-time (_ c CURLOPT_TIMEOUT max-time) (_ c CURLOPT_TIMEOUT 0))
      (when ipv4 (_ c CURLOPT_IPRESOLVE CURL_IPRESOLVE_V4))
      (when (fc "IPv6") (when ipv6 (_ c CURLOPT_IPRESOLVE CURL_IPRESOLVE_V6)))
      (if range
	  (_ c CURLOPT_RANGE range)
	  (_ c CURLOPT_RANGE #f))
      (when (vc "7.15.2")
	(when local-port
	  (cond ((#/^(\d+)(\-(\d+))?$/ local-port) 
		 => (lambda (m) 
		      (begin
			(_ c CURLOPT_LOCALPORT (string->number (m 1)))
			(when (m 3) (_ c CURLOPT_LOCALPORTRANGE (string->number (m 3)))))))
		(else <curl-error> :message "local port range is invalid."))))
      (let1 resume (if continue-at continue-at 0)
	(if (fc "Largefile")
	    (_ c CURLOPT_RESUME_FROM_LARGE resume)
	    (_ c CURLOPT_RESUME_FROM resume)))
      (when progress-bar (curl-set-progress! c #t))
      (when (vc "7.21.0")
	(begin
	  (when proto (_ c CURLOPT_PROTOCOLS (protocol->number proto)))
	  (when proto-redir (_ c CURLOPT_REDIR_PROTOCOLS (protocol->number proto-redir)))))
      ;; speed
      (when speed-time
	(begin 
	  (_ c CURLOPT_LOW_SPEED_TIME speed-time)
	  (unless speed-limit (_ c CURLOPT_LOW_SPEED_LIMIT 1))))
      (when speed-limit 
	(begin 
	  (_ c CURLOPT_LOW_SPEED_LIMIT speed-limit)
	  (unless speed-time (_ c CURLOPT_LOW_SPEED_TIME 30))))
      (when limit-rate
	(let1 rate (parse-unit limit-rate)
	  (_ c CURLOPT_BUFFERSIZE rate)
	  (_ c CURLOPT_MAX_SEND_SPEED_LARGE rate)
	  (_ c CURLOPT_MAX_RECV_SPEED_LARGE rate)))
      ;; socket function
      (unless no-keepalive
	(curl-set-socket-options hnd (if (vc "7.18.0")
					  (if keepalive-time keepalive-time 0)
					  0)))
      ;; debug
      (if verbose (_ c CURLOPT_VERBOSE 1) (_ c CURLOPT_VERBOSE 0))
      (when stderr (curl-open-file hnd CURLOPT_STDERR stderr))
      ;; HTTP
      (if user-agent (_ c CURLOPT_USERAGENT user-agent) 
	  (_ c CURLOPT_USERAGENT (string-append "Gauche/" (gauche-version) " " (curl-version))))
      (if location (_ c CURLOPT_FOLLOWLOCATION 1) (_ c CURLOPT_FOLLOWLOCATION 0)) 
      (if location-trusted (_ c CURLOPT_UNRESTRICTED_AUTH 1) (_ c CURLOPT_UNRESTRICTED_AUTH 0))
      (if max-redirs (_ c CURLOPT_MAXREDIRS max-redirs) (_ c CURLOPT_MAXREDIRS -1))
      (if request (_ c CURLOPT_CUSTOMREQUEST request) (_ c CURLOPT_CUSTOMREQUEST #f))
      (if referer
 	  (begin
	    (if (#/\;auto$/ referer) (_ c CURLOPT_AUTOREFERER 1) (_ c CURLOPT_AUTOREFERER 0))
	    (cond ((#/(^.+)\;auto$/ referer)
		   => (lambda (m) (unless (= (string-length (m 1)) 0) (_ c CURLOPT_REFERER (m 1)))))))
	  (_ c CURLOPT_REFERER #f))
      (when compressed (_ c CURLOPT_ENCODING ""))
      (if fail (_ c CURLOPT_FAILONERROR 1) (_ c CURLOPT_FAILONERROR 0))
      (when get (_ c CURLOPT_HTTPGET 1))
      (when header (_ c CURLOPT_HTTPHEADER (string-split header #\,)))
      (if head (_ c CURLOPT_NOBODY 1) (_ c CURLOPT_NOBODY 0))
      (when post301 
	(if (vc "7.19.0")
	    (_ c CURLOPT_POSTREDIR CURL_REDIR_POST_301)
	    (_ c CURLOPT_POST301)))
      (when post302 (_ c CURLOPT_POSTREDIR CURL_REDIR_POST_302))
      (when http1.0 (_ c CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_1_0))
      (when (vc "7.16.2")
	(when raw
	  (begin
	    (_ c CURLOPT_HTTP_CONTENT_DECODING 0)
	    (_ c CURLOPT_HTTP_TRANSFER_DECODING 0))))
      (when time-cond
	(cond ((#/^([\+\-\=])?(.+)$/ time-cond)
	       => (lambda (m) 
		    (let ((condition (m 1))
			  (timeval (m 2)))
		      (cond ((equal? condition "+") (_ c CURLOPT_TIMECONDITION CURL_TIMECOND_IFMODSINCE))
			    ((equal? condition "-") (_ c CURLOPT_TIMECONDITION CURL_TIMECOND_IFUNMODSINCE))
			    ((equal? condition "=") (_ c CURLOPT_TIMECONDITION CURL_TIMECOND_LASTMOD))
			    (else (_ c CURLOPT_TIMECONDITION CURL_TIMECOND_IFMODSINCE)))
		      (if (< (curl-getdate timeval) 0)
			  (if (file-exists? timeval) (_ c CURLOPT_TIMEVALUE (sys-stat->mtime (sys-stat timeval)))
			      (_ c CURLOPT_TIMECONDITION CURL_TIMECOND_NONE))
			  ;; FIXME: CURLOPT_TIMEVALUE is not reflected.
			  (_ c CURLOPT_TIMEVALUE (curl-getdate timeval))))))))
      ;; HTTP Form
      (when (or form form-string)
	(begin
	  (_ c CURLOPT_POST 1)
	  (receive (poststr boundary)
	      (apply http-compose-form-data `(,(if form (curl-parse-form-opt-string form) 
						   (curl-parse-form-opt-string form-string #t)) #f))
	    (_ c CURLOPT_POSTFIELDS poststr)
	    (slot-set! c 'http-headers (append (http-headers-of c)
					       `("Mime-Version: 1.0"
						 ,#`"Content-Type: multipart/form-data; boundary=,|boundary|"))))
	  (if (fc "Largefile")
	      (_ c CURLOPT_POSTFIELDSIZE_LARGE -1)
	      (_ c CURLOPT_POSTFIELDSIZE -1))))
      ;; output
      (if output (curl-open-output-file c output :create-dir (if create-dirs #t #f))
	  (curl-open-port hnd CURLOPT_WRITEDATA (current-output-port)))
      (when remote-name (curl-open-output-file curl
					       (let1 fn (sys-basename (values-ref (uri-parse (url-of c)) 4))
						 (if (equal? fn "") "index.html" fn))
					       :create-dir #f))
      (if remote-time (_ c CURLOPT_FILETIME 1) (_ c CURLOPT_FILETIME 0))
      (when dump-header (curl-open-header-file c dump-header :create-dir #f))
      (when max-filesize 
	(if (fc "Largefile")
	    (_ c CURLOPT_MAXFILESIZE_LARGE max-filesize)
	    (_ c CURLOPT_MAXFILESIZE max-filesize)))
      (if include (_ c CURLOPT_HEADER 1) (_ c CURLOPT_HEADER 0))
      (if interface (_ c CURLOPT_INTERFACE interface) (_ c CURLOPT_INTERFACE #f))
      (if tcp-nodelay (_ c CURLOPT_TCP_NODELAY 1) (_ c CURLOPT_TCP_NODELAY 0))
      ;; auth
      (if user (_ c CURLOPT_USERPWD user) (_ c CURLOPT_USERPWD #f))
      (when basic (_ c CURLOPT_HTTPAUTH CURLAUTH_BASIC))
      (when digest (_ c CURLOPT_HTTPAUTH CURLAUTH_DIGEST))
      (when (fc "GSS-Negotiate") (when negotiate (_ c CURLOPT_HTTPAUTH CURLAUTH_GSSNEGOTIATE)))
      (when (fc "NTLM") (when ntlm (_ c CURLOPT_HTTPAUTH CURLAUTH_NTLM)))
      (when anyauth (_ c CURLOPT_HTTPAUTH CURLAUTH_ANY))
      ;; proxy
      (if proxy 
	  (begin 
	    (_ c CURLOPT_PROXYTYPE CURLPROXY_HTTP)
	    (_ c CURLOPT_PROXY proxy))
	  (_ c CURLOPT_PROXY #f))
      (when (vc "7.15.2")
	(if socks4 
	    (begin 
	      (_ c CURLOPT_PROXYTYPE CURLPROXY_SOCKS4)
	      (_ c CURLOPT_PROXY socks4))
	    (_ c CURLOPT_PROXY #f))
	(when (vc "7.18.0")
	  (begin
	    (if socks4a 
		(begin 
		  (_ c CURLOPT_PROXYTYPE CURLPROXY_SOCKS4A)
		  (_ c CURLOPT_PROXY socks4a))
		(_ c CURLOPT_PROXY #f))
	    (if socks5
		(begin
		  (_ c CURLOPT_PROXYTYPE CURLPROXY_SOCKS5)
		  (_ c CURLOPT_PROXY socks5))
		(_ c CURLOPT_PROXY #f))
	    (if socks5-hostname
		(begin
		  (_ c CURLOPT_PROXYTYPE CURLPROXY_SOCKS5_HOSTNAME)
		  (_ c CURLOPT_PROXY socks5-hostname))
		(_ c CURLOPT_PROXY #f))))
	(when (vc "7.19.0") 
	  (when proxytunnel (_ c CURLOPT_HTTPPROXYTUNNEL 1)))
	(when (vc "7.19.4")
	  (begin
	    (if proxy1.0 
		(begin
		  (_ c CURLOPT_PROXYTYPE CURLPROXY_HTTP_1_0)
		  (_ c CURLOPT_PROXY proxy1.0))
		(_ c CURLOPT_PROXY #f)))
	  (if socks5-gssapi-nec (_ c CURLOPT_PROXYTYPE 1) (_ c CURLOPT_PROXYTYPE 0))
	  (when socks5-gssapi-service (_ c CURLOPT_SOCKS5_GSSAPI_SERVICE socks5-gssapi-service))
	  (if noproxy (_ c CURLOPT_NOPROXY noproxy) (_ c CURLOPT_NOPROXY #f))))
      (if proxy-user (_ c CURLOPT_PROXYUSERPWD proxy-user) (_ c CURLOPT_PROXYUSERPWD #f))
      (when proxy-anyauth (_ c CURLOPT_PROXYAUTH CURLAUTH_ANY))
      (when proxy-basic (_ c CURLOPT_PROXYAUTH CURLAUTH_BASIC))
      (when proxy-digest (_ c CURLOPT_PROXYAUTH CURLAUTH_DIGEST))
      (when (fc "GSS-Negotiate") (when proxy-negotiate (_ c CURLOPT_PROXYAUTH CURLAUTH_GSSNEGOTIATE)))
      (when (fc "NTLM") (when proxy-ntlm (_ c CURLOPT_PROXYAUTH CURLAUTH_NTLM)))
      ;; data upload
      (when upload-file 
	(begin
	  (_ c CURLOPT_UPLOAD 1)
	  (curl-open-input-file c upload-file)
	  (if (fc "Largefile")
	      (_ c CURLOPT_INFILESIZE_LARGE (slot-ref (sys-stat upload-file) 'size))
	      (_ c CURLOPT_INFILESIZE (slot-ref (sys-stat upload-file) 'size)))
	  (when (#/^http/ (url-of c))
	    (let1 purl (string-append  
			(url-of c) (if (#/\/$/ (url-of c)) "" "/") (uri-encode-string upload-file))
	      (_ c CURLOPT_URL purl)
	      (slot-set! c 'url url)))))
      (when data
	(begin
	  (_ c CURLOPT_POST 1)
	  (if (#/^@/ data) (curl-open-input-file c data) (_ c CURLOPT_POSTFIELDS data))
	  (if (fc "Largefile")
	      (_ c CURLOPT_POSTFIELDSIZE_LARGE -1)
	      (_ c CURLOPT_POSTFIELDSIZE -1))))
      (when data-binary
	(begin
	  (_ c CURLOPT_POST 1)
	  (if (#/^@/ data-binary) (curl-open-input-file c data-binary) (_ c CURLOPT_POSTFIELDS data-binary))
	  (if (fc "Largefile")
	      (_ c CURLOPT_POSTFIELDSIZE_LARGE -1)
	      (_ c CURLOPT_POSTFIELDSIZE -1))))
      (when data-urlencode
	  (begin
	    (_ c CURLOPT_POST 1)
	    (cond ((#/^(.+?)@(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ c CURLOPT_POSTFIELDS
			   (string-append 
			    (m 1) "=" 
			    (uri-encode-string (call-with-input-file (m 2) (cut port->string <>)))))))
		  ((#/^(.+?)=(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ c CURLOPT_POSTFIELDS
			   (string-append 
			    (m 1) "="
			    (uri-encode-string (m 2))))))
		  ((#/^@(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ c CURLOPT_POSTFIELDS
			   (uri-encode-string (call-with-input-file (m 1) (cut port->string <>))))))
		  ((#/^=(.+)$/ data-urlencode) 
		   => (lambda (m) 
			(_ c CURLOPT_POSTFIELDS
			   (uri-encode-string (m 1)))))
		  (else  
		   (_ c CURLOPT_POSTFIELDS (uri-encode-string data-urlencode))))
	    (if (fc "Largefile")
		(_ c CURLOPT_POSTFIELDSIZE_LARGE -1)
		(_ c CURLOPT_POSTFIELDSIZE -1))))
      (if ignore-content-length (_ c CURLOPT_IGNORE_CONTENT_LENGTH 1) (_ c CURLOPT_IGNORE_CONTENT_LENGTH 0))
      ;; cookie
      (if junk-session-cookies (_ c CURLOPT_COOKIESESSION 0) (_ c CURLOPT_COOKIESESSION 1))
      (if cookie 
	  (cond ((#/=/ cookie) 
		 (_ c CURLOPT_COOKIE cookie))
		(else 
		 (_ c CURLOPT_COOKIEFILE cookie)))
	  (begin
	    (_ c CURLOPT_COOKIE #f)
	    (_ c CURLOPT_COOKIEFILE #f)))
      (if cookie-jar (_ c CURLOPT_COOKIEJAR cookie-jar) (_ c CURLOPT_COOKIEJAR #f))
      ;; SSL
      (when (fc "SSL")
	(begin
	  (when (vc "7.19.1") (_ c CURLOPT_CERTINFO 1))
	  (when tlsv1 (_ c CURLOPT_SSLVERSION CURL_SSLVERSION_TLSv1))
	  (when sslv2 (_ c CURLOPT_SSLVERSION CURL_SSLVERSION_SSLv2))
	  (when sslv3 (_ c CURLOPT_SSLVERSION CURL_SSLVERSION_SSLv3))
	  (when cacert (_ c CURLOPT_SSLCERT cacert))
	  (when capath (_ c CURLOPT_CAPATH capath))
	  (when cert-type 
	    (cond ((equal? cert-type "PEM") (_ c CURLOPT_SSLCERTTYPE cert-type))
		  ((equal? cert-type "DER") (_ c CURLOPT_SSLCERTTYPE cert-type))
		  (else (error <curl-error> :message "SSL CERT type is invalid."))))
	  (when ciphers (_ c CURLOPT_SSL_CIPHER_LIST ciphers))
	  (when random-file (_ c CURLOPT_RANDOM_FILE random-file))
	  (when egd-file (_ c CURLOPT_EGDSOCKET egd-file))
	  (when engine (_ c CURLOPT_SSLENGINE engine))
	  (when (vc "7.16.0")
	    (begin
	      (when sessionid (_ c CURLOPT_SSL_SESSIONID_CACHE 1))
	      (when no-sessionid (_ c CURLOPT_SSL_SESSIONID_CACHE 0))))
	  (when cert 
	    (cond ((#/^(.+):(.+)$/ cert) 
		   => (lambda (m) 
			(begin
			  (_ c CURLOPT_SSLKEY (m 1))
			  (cond 
			   ((vc "7.16.5") (_ c CURLOPT_KEYPASSWD (m 2)))
			   ((vc "7.9.3") (_ c CURLOPT_SSLKEYPASSWD (m 2)))
			   (else (_ c CURLOPT_CERTKEYPASSWD (m 2)))))))
		  (else (_ c c CURLOPT_SSLKEY cert))))
	  (when key 
	    (cond 
	     ((vc "7.16.5") (_ c CURLOPT_KEYPASSWD key))
	     ((vc "7.9.3") (_ c CURLOPT_SSLKEYPASSWD key))
	     (else (_ c CURLOPT_CERTKEYPASSWD key))))
	  (when pass 
	    (cond 
	     ((vc "7.16.5") (_ c CURLOPT_KEYPASSWD pass))
	     ((vc "7.9.3") (_ c CURLOPT_SSLKEYPASSWD pass))
	     (else (_ c CURLOPT_CERTKEYPASSWD pass))))
	  (when key-type 
	    (cond ((equal? key-type "PEM") (_ c CURLOPT_SSLKEYTYPE key-type))
		  ((equal? key-type "DER") (_ c CURLOPT_SSLKEYTYPE key-type))
		  ((equal? key-type "ENG") (_ c CURLOPT_SSLKEYTYPE key-type))
		  (else (error <curl-error> :message "SSL private key type is invalid."))))
	  (when insecure 
	    (begin
	      (_ c CURLOPT_SSL_VERIFYPEER #f)
	      (_ c CURLOPT_SSL_VERIFYHOST 1)))
	  (when (and (not cacert) (not capath) (not insecure))
	    (let1 env (sys-getenv "CURL_CA_BUNDLE")
	      (if env (_ c CURLOPT_SSLCERT env)
		  (let1 env (sys-getenv "SSL_CERT_DIR")
		    (if env (_ c CURLOPT_CAPATH env)
			(let1 env  (sys-getenv "SSL_CERT_FILE")
			  (when env (_ c CURLOPT_SSLCERT env))))))))
	  (when (vc "7.17.7") (when crlfile (_ c CURLOPT_CRLFILE crlfile)))
	  (when (vc "7.20.0") 
	    (begin (when ssl (_ c CURLOPT_USE_SSL CURLUSESSL_TRY))
		   (when ssl-reqd (_ c CURLOPT_USE_SSL CURLUSESSL_ALL))))))
      ;; SSH
      (when (pc "scp")
	(begin
	  (_ c CURLOPT_SSH_AUTH_TYPES CURLSSH_AUTH_DEFAULT)
	  (when key (_ c CURLOPT_SSH_PRIVATE_KEYFILE key))
	  (when pubkey (_ c CURLOPT_SSH_PUBLIC_KEYFILE pubkey))
	  (when hostpubmd5 (_ c CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 hostpubmd5))
	  (when pass (cond 
		      ((vc "7.16.5") (_ c CURLOPT_KEYPASSWD pass))
		      ((vc "7.9.3") (_ c CURLOPT_SSLKEYPASSWD pass))
		      (else (_ c CURLOPT_CERTKEYPASSWD pass))))
	  (when (and (vc "7.19.6") (not insecure) (libssh2c "1.2"))
	    (when (home-directory)
	      (_ c CURLOPT_SSH_KNOWNHOSTS (string-append (home-directory) "/.ssh/known_hosts"))))))
      ;; FTP
      (when (pc "ftp")
	(begin
	  (if ftp-port (_ c CURLOPT_FTPPORT ftp-port) (_ c CURLOPT_FTPPORT #f))
	  (when ftp-pasv (_ c CURLOPT_FTPPORT #f))
	  (when quote-opt (_ c CURLOPT_QUOTE (curl-list->curl-slist (string-split quote-opt #\,))))
	  (when list-only 
	    (when (vc "7.16.5") (_ c CURLOPT_DIRLISTONLY 1) (_ c CURLOPT_FTPLISTONLY 1)))
	  (when append-opt 
	    (when (vc "7.16.5")  (_ c CURLOPT_APPEND 1) (_ c CURLOPT_FTPAPPEND 1)))
	  (when use-ascii (_ c CURLOPT_TRANSFERTEXT 1))
	  (cond ((#/^(.+)\;type\=A$/ (url-of c)) 
		 => (lambda (m) 
		      (begin
			(_ c CURLOPT_URL (m 1))
			(slot-set! c 'url (m 1))
			(_ c CURLOPT_TRANSFERTEXT 1)))))
	  (when crlf (_ c CURLOPT_CRLF 1))
	  (when (vc "7.10.5")
	    (begin
	      (if disable-eprt (_ c CURLOPT_FTP_USE_EPRT 0) (_ c CURLOPT_FTP_USE_EPRT 1))
	      (if no-eprt (_ c CURLOPT_FTP_USE_EPRT 0) (_ c CURLOPT_FTP_USE_EPRT 1))
	      (if eprt (_ c CURLOPT_FTP_USE_EPRT 1) (_ c CURLOPT_FTP_USE_EPRT 0))))
	  (if disable-epsv (_ c CURLOPT_FTP_USE_EPSV 0) (_ c CURLOPT_FTP_USE_EPSV 1))
	  (if no-epsv (_ c CURLOPT_FTP_USE_EPSV 0) (_ c CURLOPT_FTP_USE_EPSV 1))
	  (if epsv (_ c CURLOPT_FTP_USE_EPSV 1) (_ c CURLOPT_FTP_USE_EPSV 0))
	  (when (vc "7.10.7") (when ftp-create-dirs (_ c CURLOPT_FTP_CREATE_MISSING_DIRS 2)))
	  (when (vc "7.13.0")  (when ftp-account (_ c CURLOPT_FTP_ACCOUNT ftp-account)))
	  (when (vc "7.14.2") (when ftp-skip-pasv-ip (_ c CURLOPT_FTP_SKIP_PASV_IP 1)))
	  (when (vc "7.15.1")
	    (when ftp-method
	      (cond ((equal? ftp-method "multicwd") (_ c CURLOPT_FTP_FILEMETHOD CURLFTPMETHOD_MULTICWD))
		    ((equal? ftp-method "nocwd") (_ c CURLOPT_FTP_FILEMETHOD CURLFTPMETHOD_NOCWD))
		    ((equal? ftp-method "singlecwd") (_ c CURLOPT_FTP_FILEMETHOD CURLFTPMETHOD_SINGLECWD))
		    (else (error <curl-error> :message "ftp method is invalid.")))))
	  (when (vc "7.15.5") (when ftp-alternative-to-user (_ c CURLOPT_FTP_ALTERNATIVE_TO_USER ftp-alternative-to-user)))
	  (when (fc "GSS-Negotiate") (when krb 
				       (when (vc "7.16.4") (_ c CURLOPT_KRBLEVEL krb)
					     (_ c CURLOPT_KRB4LEVEL krb))))
	  (when (pc "ftps")
	    (when (vc "7.16.5")
	      (begin
		(when ftp-ssl (_ c CURLOPT_USE_SSL CURLUSESSL_TRY))
		(when ftp-ssl-control (_ c CURLOPT_USE_SSL CURLUSESSL_CONTROL))
		(when ftp-ssl-reqd (_ c CURLOPT_USE_SSL CURLUSESSL_ALL))))
	    (when ftp-ssl-ccc (_ c CURLOPT_FTP_SSL_CCC CURLFTPSSL_CCC_PASSIVE))
	    (when ftp-ssl-ccc-mode
	      (cond ((equal? ftp-ssl-ccc-mode "active") (_ c CURLOPT_FTP_SSL_CCC CURLFTPSSL_CCC_ACTIVE))
		    ((equal? ftp-ssl-ccc-mode "passive") (_ c CURLOPT_FTP_SSL_CCC CURLFTPSSL_CCC_PASSIVE))
		    (else (error <curl-error> :message "ftp ssl ccc mode is invalid.")))))
	  (when ftp-pret (when (vc "7.20.0") (_ c CURLOPT_FTP_USE_PRET #t)))))
      ;; LDAP
      (when (pc "ldap")
	(when use-ascii (_ c CURLOPT_TRANSFERTEXT) 1))
      ;; telnet
      (when (pc "telnet")
	(when telnet-option (_ c CURLOPT_TELNETOPTIONS (curl-list->curl-slist (string-split telnet-option #\,)))))
      ;; tftp
      (when (and (pc "tftp") (vc "7.20.0"))
	(_ c CURLOPT_TFTP_BLKSIZE tftp-blksize))
      ;; SMTP
      (when (and (pc "smtp") (vc "7.20.0"))
	(when mail-rcpt	(_ c CURLOPT_MAIL_RCPT (string-split mail-rcpt #\,)))
	(when mail-from (_ c CURLOPT_MAIL_FROM mail-from))))))


;;; procedure

;; easy interface
(define-method curl-setopt! ((curl <curl>) opt val)
  (let1 hnd (handler-of curl)
    (if hnd 
	(let1 res (curl-easy-setopt hnd opt (if (list? val) 
						(curl-list->curl-slist val) val))
	  (slot-set! curl 'rc res)
	  (when (equal? opt CURLOPT_HTTPHEADER)
	    (unless (equal? (http-headers-of curl) val)
	      (set! (http-headers-of curl) (append (http-headers-of curl) val))))
	  (if (= res CURLE_OK) #t 
	      (error <curl-error> :message (curl-strerror curl))))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-perform ((curl <curl>))
  (let1 hnd (handler-of curl)
    (unless (null? (http-headers-of curl))
      (curl-setopt! curl CURLOPT_HTTPHEADER (http-headers-of curl)))
    (if hnd (let1 res (curl-easy-perform hnd)
	      (slot-set! curl 'rc res)
	      (when (and (slot-ref curl 'reuse) enthread?)
		(begin
		  (put-pool hnd)
		  (slot-set! curl 'info (curl-getinfo curl))))
	      (cond ((= res CURLE_OK) #t)
		    (else (error <curl-error> :message (curl-strerror curl)))))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-strerror ((curl <curl>))
  (if (vc "7.12.0")
      (if (rc-of curl) 
	  (curl-easy-strerror (rc-of curl))
	  #f)
      (error <curl-error> "This method is unsupported in this version of libcurl.")))

(define-method curl-getinfo ((curl <curl>))
  (let1 info (slot-ref curl 'info)
    (if info info
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
			,(if (vc "7.19.4") (cons 'CONDITION_UNMET (_ hnd CURLINFO_CONDITION_UNMET)) #f)
			,(if (vc "7.20.1") (cons 'PRIMARY_PORT (_ hnd CURLINFO_PRIMARY_PORT)) #f)
			,(if (vc "7.20.1") (cons 'LOCAL_IP (_ hnd CURLINFO_LOCAL_IP)) #f)
			,(if (vc "7.20.1") (cons 'LOCAL_PORT (_ hnd CURLINFO_LOCAL_PORT)) #f)))
	      (error <curl-error> :message "curl handler is invalid."))))))

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
		(else (error <curl-error> :message (curl-strerror curl)))))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-reset! ((curl <curl>))
  (let1 hnd (handler-of curl)
    (if hnd
	(let1 res (curl-easy-reset hnd)
	  (cond ((undefined? res)
		 (curl-setopt! curl CURLOPT_URL (url-of curl))
		 (slot-set! curl 'rc #f)
		 #t)
		(else (error <curl-error> :message (curl-strerror curl)))))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-pause ((curl <curl>) . direction)
  (if (vc "7.18.0")
      (let1 res
	  (if (null? direction)
	      (curl-easy-pause (handler-of curl) CURLPAUSE_ALL)
	      (cond ((eq (car direction) 'SEND)
		     (curl-easy-pause (handler-of curl) CURLPAUSE_SEND))
		    ((eq (car direction) 'RECV)
		     (curl-easy-pause (handler-of curl) CURLPAUSE_RECV))
		    (else 
		     (error <curl-error> :message "Pause direction is invalid(only SEND or RECV)."))))
	(slot-set! curl 'rc res)
	(if (= rc CURLE_OK) #t 
	    (error <curl-error> :message (curl-strerror curl))))
      (error <curl-error> "This method is unsupported in this version of libcurl.")))

(define-method curl-unpause ((curl <curl>))
  (if (vc "7.18.0")
      (let1 res (curl-easy-pause (handler-of curl) CURLPAUSE_CONT)
	(slot-set! curl 'rc res)
	(if (= res CURLE_OK) #t 
	    (error <curl-error> :message (curl-strerror curl))))
      (error <curl-error> "This method is unsupported in this version of libcurl.")))

;; multi interface
(define-method curl-setopt! ((curlm <curl-multi>) opt val)
  (if (vc "7.15.4")
      (let1 hnd (handler-of curlm)
	(if hnd 
	    (let1 res (curl-multi-setopt (handler-of curlm) opt val)
	      (slot-set! curlm 'rc res)
	      (if (= res CURLM_OK) #t 
		  (error <curl-error> :message (curl-strerror curl))))
	    (error <curl-error> :message "curl multi handler is invalid.")))
      (error <curl-error> "This method is unsupported in this version of libcurl.")))

(define-method curl-timeout! ((curlm <curl-multi>) seconds)
  (let1 hnd (handler-of curlm)
    (if hnd 
	(let1 res (curl-multi-timeout (handler-of curlm) seconds)
	  (slot-set! curlm 'rc res)
	  (if (= res CURLM_OK) #t 
	      (error <curl-error> :message (curl-strerror curl))))
	(error <curl-error> :message "curl multi handler is invalid."))))

(define-method curl-handler-add! ((curlm <curl-multi>) (curl <curl>))
  (let1 res (curl-multi-add-handle (handler-of curlm) (handler-of curl))
    (slot-set! curlm 'rc res)
    (if (= res CURLM_OK)
	(begin
	  (slot-set! curlm 'handlers (append (handlers-of curlm) (list curl)))
	  (undefined))
	(error <curl-error> :message (curl-strerror curlm)))))

(define-method curl-handler-remove! ((curlm <curl-multi>) (curl <curl>))
  (let1 res (curl-multi-remove-handle (handler-of curlm) (handler-of curl))
    (slot-set! curlm 'rc res)
    (if (= res CURLM_OK)
	(begin
	  (slot-set! curlm 'handlers (remove (cut eq? <> curl) (handlers-of curlm)))
	  (undefined))
	(error <curl-error> :message (curl-strerror curlm)))))

(define-method curl-perform ((curlm <curl-multi>))
  (let1 res (curl-multi-perform (handler-of curlm))
    (slot-set! curlm 'rc (car res))
    (slot-set! curlm 'remains (cdr res))
    (update-multi-results! curlm)
    (if (<= (slot-ref curlm 'rc) CURLM_OK) #t
	(error <curl-error> :message (curl-strerror curlm)))))

(define-method curl-cleanup! ((curlm <curl-multi>))
  (let1 hnd (handler-of curlm)
    (if hnd
	(let1 res (curl-multi-cleanup hnd)
	  (cond ((= res CURLM_OK)
		 (for-each (cut curl-cleanup! <>) (handlers-of curlm))
		 (slot-set! curlm 'handlers '())
		 (slot-set! curlm 'rc #f)
		 #t)
		(else 
		 (slot-set! curlm 'rc rc)
		 (error <curl-error> :message (curl-strerror curlm)))))
	(error <curl-error> :message "curl multi handler is invalid."))))

(define-method curl-strerror ((curlm <curl-multi>))
  (if (vc "7.12.0")
      (if (rc-of curlm) 
	  (curl-multi-strerror (rc-of curlm))
	  #f)
      (error <curl-error> "This method is unsupported in this version of libcurl.")))

(define-method curl-multi-info->list ((curlm <curl-multi>))
  (_curl-multi-info->list (handler-of curlm)))

(define-method update-multi-results! ((curlm <curl-multi>))
  (for-each
   (lambda (curl) 
     (for-each 
      (lambda (result) (when (eq? (handler-of curl) (cdr result)) (slot-set! curl 'rc (car result))))
      (curl-multi-info->list curlm)))
   (handlers-of curlm)))

(define-method curl-fdset ((curlm <curl-multi>))
  (curl-multi-fdset (handler-of curlm)))

(define-method curl-async-perform ((curlm <curl-multi>))
  (curl-perform curlm)
  (do ((#f #f (curl-perform curlm)))
      ((= (remains-of curlm) 0) (handlers-of curlm))
    (apply sys-select (append (curl-fdset curlm) '(50000)))))

;; share interface
(define-method curl-setopt! ((share <curl-share>) opt val)
  (let1 hnd (handler-of share)
    (if hnd 
	(let1 res (curl-share-setopt (handler-of share) opt val)
	  (slot-set! share 'rc res)
	  (if (= res CURLSHE_OK) #t 
	      (error <curl-error> :message (curl-strerror share))))
	(error <curl-error> :message "curl share handler is invalid."))))

(define-method curl-cleanup! ((share <curl-share>))
  (let1 hnd (handler-of share)
    (if hnd
	(let1 res (curl-share-cleanup hnd)
	  (slot-set! share 'rc res)
	  (if (= res CURLSHE_OK) #t 
	      (error <curl-error> :message (curl-strerror share))))
	(error <curl-error> :message "curl share handler is invalid."))))

(define-method curl-strerror ((share <curl-share>))
  (if (vc "7.12.0")
      (if (rc-of share) 
	  (curl-share-strerror (rc-of share))
	  #f)
      (error <curl-error> "This method is unsupported in this version of libcurl.")))

;; I/O
(define-method curl-open-output-file ((curl <curl>) filename . opts)
  (let-keywords opts 
		((create-dir :create-dir #f)
		 . opt)
		(let1 hnd (handler-of curl)
		  (if hnd
		      (curl-open-file hnd CURLOPT_WRITEDATA 
				      (check-and-create-directory filename create-dir))
		      (error <curl-error> :message "curl handler is invalid.")))))

(define-method curl-open-input-file ((curl <curl>) filename)
  (let ((hnd (handler-of curl))
	(fn (sys-normalize-pathname filename :expand #t  :canonicalize #t :absolute #t)))
    (unless (file-is-regular? fn) 
      (error <curl-error> :message (string-append filename " doesn't exist, or not readable.")))
    (if hnd
	(begin0 
	  (curl-open-file hnd CURLOPT_READDATA fn)
	  (curl-setopt! curl CURLOPT_POSTFIELDS #f)
	  (if (fc "Largefile")
	      (curl-setopt! curl CURLOPT_POSTFIELDSIZE_LARGE -1)
	      (curl-setopt! curl CURLOPT_POSTFIELDSIZE -1)))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-open-header-file ((curl <curl>) filename . opts)
  (let-keywords opts 
		((create-dir :create-dir #f)
		 . opt)
		(let1 hnd (handler-of curl)
		  (if hnd
		      (curl-open-file hnd CURLOPT_WRITEHEADER 
				      (check-and-create-directory filename create-dir))
		      (error <curl-error> :message "curl handler is invalid.")))))

(define-method curl-open-error-file ((curl <curl>) filename . opts)
  (let-keywords opts 
		((create-dir :create-dir #f)
		 . opt)
		(let1 hnd (handler-of curl)
		  (if hnd
		      (curl-open-file hnd CURLOPT_STDERR 
				      (check-and-create-directory filename create-dir))
		      (error <curl-error> :message "curl handler is invalid.")))))

(define-method curl-open-output-port ((curl <curl>) . out)
  (let1 hnd (handler-of curl)
    (if hnd
	(curl-open-port hnd CURLOPT_WRITEDATA 
			(if (null? out)
			    (open-output-string)
			    (if (output-port? (car out)) (car out)
				(error <curl-error> :message "You must set an output port."))))
	(error <curl-error> :message "curl handler is invalid."))))

(define-method curl-open-input-port ((curl <curl>) in)
  (let1 hnd (handler-of curl)
    (if hnd
	(begin0
	  (curl-open-port hnd CURLOPT_READDATA
			  (if (input-port? in) in
			      (else (error <curl-error> :message "You must set an input port."))))
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
				(error <curl-error> :message "You must set an output port."))))
	(error <curl-error> :message "curl handler is invalid."))))


;;; utils
(define (curl-headers->alist headers-str . num)
  (let1 ls (remove null? (map (lambda  (h) (rfc822-read-headers (open-input-string h)))
			      (string-split headers-str "\r\n\r\n")))
    (if (null? num) ls
	(let1 n (car num)
	  (if (>= n 0) (list-ref ls n)
	      (list-ref ls (- (length ls) 1)))))))

(define (curl-parse-form-opt-string form . nofile)
  (cond ((string? form)
	 (apply parse-form-opt-string form nofile))
	((list? form)
	 (append-map (lambda (f) (apply curl-parse-form-opt-string f nofile)) form))
	(else (error <curl-error> :message "a form option string of curl(1) or string's list required."))))

(define-method curl-set-http-form! ((curl <curl>) form . nofile)
  (curl-setopt! curl CURLOPT_POST 1)
  (receive (poststr boundary)
      (apply http-compose-form-data `(,(if (null? nofile) (curl-parse-form-opt-string form) 
					   (curl-parse-form-opt-string form #t)) #f))
    (curl-setopt! curl CURLOPT_POSTFIELDS poststr)
    (slot-set! curl 'http-headers (append (http-headers-of curl)
					  `("Mime-Version: 1.0"
					    ,#`"Content-Type: multipart/form-data; boundary=,|boundary|"))))
  (if (fc "Largefile")
      (curl-setopt! curl CURLOPT_POSTFIELDSIZE_LARGE -1)
      (curl-setopt! curl CURLOPT_POSTFIELDSIZE -1)))


;;; progress functions
(define-method curl-set-progress! ((curl <curl>) . show-bar)
  (if (not (slot-ref curl 'progress))
      (if (null? show-bar)
	  (slot-set! curl 'progress (curl-set-progress-options (handler-of curl)))
	  (slot-set! curl 'progress (curl-set-progress-options-show (handler-of curl))))
      (slot-ref curl 'progress)))

(define-method curl-get-progress ((curl <curl>))
  (if (slot-ref curl 'progress)
      (curl-get-progress-numbers (slot-ref curl 'progress))
      '()))


;;; wrapper procedure
;; Common
(define (http-common method hostname path body . opts)
  (let-keywords opts ((sink :sink #f)
		      (flusher :flusher #f)
		      (host :host #f)
		      (secure :secure #f)
		      (no-redirect :no-redirect #f)
		      (auth-handler :auth-handler #f)
		      (auth-user :auth-user #f)
		      (auth-password :auth-password #f)
		      (request-encoding :request-encoding (gauche-character-encoding))
		      (proxy :proxy #f)
		      (ssl :ssl #f)
		      (verbose :verbose #f)
		      (options :options #f)
		      . opt)
		(let* ((curl (make <curl> :url (string-append (if (or secure ssl) "https://" "http://") hostname 
							      (ensure-request-uri path request-encoding))))
		       (output (if (not sink) (curl-open-output-port curl)
				   (curl-open-output-port curl sink)))
		       (header-output (curl-open-header-port curl))
		       (headers opt))
		  (when verbose (curl-setopt! curl CURLOPT_VERBOSE 1))
		  (if (eq? method 'HEAD) (curl-setopt! curl CURLOPT_NOBODY 1)
		      (curl-setopt! curl CURLOPT_CUSTOMREQUEST (symbol->string method)))
		  (curl-setopt! curl CURLOPT_USERAGENT (http-user-agent))
		  (curl-setopt! curl CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_NONE)
		  (curl-setopt! curl CURLOPT_ENCODING "") ; "Content-Encoding: deflate, gzip", not compatible with rfc.http?
		  (when host (set! headers (append `(:Host ,host) headers)))
		  (when body 
		    (cond ((string? body) (curl-setopt! curl CURLOPT_POSTFIELDS body))
			  ((list? body)
			   (receive (body boundary) (http-compose-form-data body #f request-encoding) ; rfc.http of Gauche 0.9
			     (curl-setopt! curl CURLOPT_POSTFIELDS body)
			     (set! headers `(:Mime-Version "1.0"
					     :Content-Type ,#`"multipart/form-data; boundary=,boundary"
					     ,@(delete-keyword! :Content-Type headers)))))
			  (else (error "Invalid request-body format:" body))))
		  (if no-redirect (curl-setopt! curl CURLOPT_FOLLOWLOCATION 0)
		      (curl-setopt! curl CURLOPT_FOLLOWLOCATION 1))
		  (when (and auth-user auth-password) 
		      (curl-setopt! curl CURLOPT_USERPWD (string-append auth-user ":" auth-password)))
		  (when auth-handler (curl-setopt! curl CURLOPT_HTTPAUTH CURLAUTH_ANY))
		  (when proxy (begin 
				(curl-setopt! curl CURLOPT_PROXYTYPE CURLPROXY_HTTP)
				(curl-setopt! curl CURLOPT_PROXY proxy)))
		  (unless (null? headers)
		    (curl-setopt! curl CURLOPT_HTTPHEADER
				  (map (lambda (h) (string-append (keyword->string (car h)) ": " (cadr h))) (slices headers 2))))
		  ;; 'options' adds setting unconfigable options from http-* interface, 
		  ;;  like ":options `((,CURLOPT_SSL_VERIFYPEER . #f)(,CURLOPT_SSL_VERIFYHOST . 1)))"
		  (when options
		    (for-each (lambda (set) (curl-setopt! curl (car set) (cdr set))) options))
		  (guard (exc ((condition-has-type? exc <curl-error>)
			       (error <http-error> (slot-ref exc 'message))))
			 (when (curl)
			   (values
			    (number->string (cdr (assq 'RESPONSE_CODE (curl-getinfo curl))))
			    (curl-headers->alist (get-output-string header-output) -1)
			    (if (eq? method 'HEAD) #f
				(if flusher (flusher output header-output)
				    (get-output-string output)))))))))

(define (ensure-request-uri request-uri enc) ; copy from rfc.http of Gauche 0.9
  (match request-uri
    [(? string?) request-uri]
    [(path n&v ...) (http-compose-query path n&v enc)]
    [_ (error "Invalid request-uri form for http request API:" request-uri)]))

(http-user-agent (string-append "gauche.http/" (gauche-version) " (" (curl-version) ")"))

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

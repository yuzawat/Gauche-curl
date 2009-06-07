;;; -*- coding: utf-8; mode: scheme -*-
;;;
;;; curl
;;;
;;; (recieve (res head body)
;;; 	 (let1 curl 
;;; 	     (make <cURL> :url "http://example.tld/test/" 
;;; 		   :options "-X GET -H Content-Type:application/atom+xml")
;;; 	   (connect curl)))

(define-module curl
  (use gauche.parseopt)
  (use gauche.parameter)
  (use rfc.uri)
  (export 
   <curl>
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

   curl-version
   curl-version-info

   ;; cooked function
   curl-open-output-file
   curl-open-header-file
   curl-open-output-port
   curl-open-header-port

   curl-open-file
   curl-open-port

handler-of
   list->curl-slist
   curl-slist->list

   ;; procedure
   curl-setopt!
   curl-perform
   curl-getinfo
   curl-reset!
   curl
   http-get
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

;; curl easy 
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
	   :accessor options-of)))

(define-method initialize ((curl <curl>) initargs)
  (next-method)
  (slot-set! curl 'handler (curl-easy-init))
  (if (slot-bound? curl 'url)
      (curl-setopt! curl CURLOPT_URL (url-of curl))))

(define-method object-apply ((curl <curl>))
  (curl-perform curl))

(define-method curl-setopt! ((curl <curl>) opt val)
  (let1 res (curl-easy-setopt (handler-of curl) opt val)
    (if (= res 0) #t #f)))

(define-method curl-perform ((curl <curl>))
  (let* ((hnd (handler-of curl))
	 (res (curl-easy-perform hnd)))
    (slot-set! curl 'code res)
    (cond ((= res 0) #t)
	  (else #f))))

(define-method curl-getinfo ((curl <curl>))
  (let* ((hnd (handler-of curl))
	 (_ curl-easy-getinfo)
	 (features (cdr (assoc "features" (curl-version-info))))
	 (protocols (cdr (assoc "protocols" (curl-version-info))))
	 (scheme (values-ref (uri-parse (url-of curl)) 0)))
    (if (code-of curl)
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
	  ,(cons 'SSL_VERIFYRESULT (_ hnd CURLINFO_SSL_VERIFYRESULT))
	  ,(cons 'FILETIME (_ hnd CURLINFO_FILETIME))
	  ,(cons 'CONTENT_LENGTH_DOWNLOAD (_ hnd CURLINFO_CONTENT_LENGTH_DOWNLOAD))
	  ,(cons 'CONTENT_LENGTH_UPLOAD (_ hnd CURLINFO_CONTENT_LENGTH_UPLOAD))
	  ,(cons 'STARTTRANSFER_TIME (_ hnd CURLINFO_STARTTRANSFER_TIME))
	  ,(cons 'CONTENT_TYPE (_ hnd CURLINFO_CONTENT_TYPE))
	  ,(cons 'REDIRECT_TIME (_ hnd CURLINFO_REDIRECT_TIME))
	  ,(cons 'REDIRECT_COUNT (_ hnd CURLINFO_REDIRECT_COUNT))
;;       ,(cons 'PRIVATE (_ hnd CURLINFO_PRIVATE))
	  ,(cons 'HTTP_CONNECTCODE (_ hnd CURLINFO_HTTP_CONNECTCODE))
	  ,(cons 'HTTPAUTH_AVAIL (_ hnd CURLINFO_HTTPAUTH_AVAIL))
	  ,(cons 'PROXYAUTH_AVAIL (_ hnd CURLINFO_PROXYAUTH_AVAIL))
	  ,(cons 'OS_ERRNO (_ hnd CURLINFO_OS_ERRNO))
	  ,(cons 'NUM_CONNECTS (_ hnd CURLINFO_NUM_CONNECTS))
;;       ,(cons 'SSL_ENGINES (_ hnd CURLINFO_SSL_ENGINES))
;;	  ,(cons 'COOKIELIST (_ hnd CURLINFO_COOKIELIST))
	  ,(cons 'LASTSOCKET (_ hnd CURLINFO_LASTSOCKET))
;	  ,(when ((#/ftp/ scheme)) (cons 'FTP_ENTRY_PATH (_ hnd CURLINFO_FTP_ENTRY_PATH)))
	  ,(cons 'REDIRECT_URL (_ hnd CURLINFO_REDIRECT_URL))
;;      ,(cons 'PRIMARY_IP (_ hnd CURLINFO_PRIMARY_IP))
;;      ,(cons 'APPCONNECT_TIME (_ hnd CURLINFO_APPCONNECT_TIME))
;;      ,(cons 'CERTINFO (_ hnd CURLINFO_CERTINFO))
	  )
	#f)))

(define-method curl-reset! ((curl <curl>))
  (let* ((hnd (handler-of curl))
	 (res (curl-easy-reset hnd)))
    (cond ((undefined? res)
	   (curl-setopt! curl CURLOPT_URL (url-of curl))
	   (slot-set! curl 'code #f)
	   #t)
	  (else #f))))

(define-method curl-open-output-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (curl-open-file hnd CURLOPT_WRITEDATA filname)))

(define-method curl-open-header-file ((curl <curl>) filename)
  (let1 hnd (handler-of curl)
    (curl-open-file hnd CURLOPT_WRITEHEADER filname)))
	 
(define-method curl-open-output-port ((curl <curl>) . filename)
  (let ((hnd (handler-of curl))
	(fn (if (null? filename) #f (car filename))))
    (if fn (curl-open-port hnd CURLOPT_WRITEDATA (open-output-file fn))
	(curl-open-port hnd CURLOPT_WRITEDATA (open-output-string)))))

(define-method curl-open-header-port ((curl <curl>) . filename)
  (let ((hnd (handler-of curl))
	(fn (if (null? filename) #f (car filename))))
    (if fn (curl-open-port hnd CURLOPT_WRITEHEADER (open-output-file fn))
	(curl-open-port hnd CURLOPT_WRITEHEADER (open-output-string)))))

(define-method %easy-options ((hnd <curl>) args)
  (let ((argls (if (string? args) (string-split args #/\s+/) args))
	(hnd (handler-of curl))
	(_ curl-easy-setopt))
    (let-args args
	((user-agent "A|user-agent=s" #f)
	 (location "L|location" #f)
	 (request "X|request=s" #f)
	 (output "o|output=s" #f)
	 (remote-name "O|remote-name" #f)
	 (verbose "v|verbose" #f)
	 (ignore-content-length "ignore-content-length" #f)
	 (referer "e|referer=s" #f)
	 (proxy "x|proxy=s" #f)
	 (interface "interface=s" #f))
      (if user-agent (_ hnd CURLOPT_USERAGENT user-agent) 
	  (_ hnd CURLOPT_USERAGENT (string-append "Gauche " (gauche-version) "/libcurl " (curl-version))))
      (when location (_ hnd CURLOPT_FOLLOWLOCATION 1)) 
      (when request (_ hnd CURLOPT_CUSTOMREQUEST request))
      (if output (curl-open-output-file hnd output) (curl-open-output-port hnd (current-output-port)))
      (when remote-name 
	(curl-open-output-file hnd 
			       (let1 fn (sys-basename (value-ref (uri-parse (url-of hnd)) 4))
				 (if (equal? fn "") index.html fn))))
      (when verbose (_ hnd CURLOPT_VERBOSE 1))
      (when ignore-content-length (_ hnd CURLOPT_IGNORE_CONTENT_LENGTH 1))
      (when referer (_ hnd CURLOPT_REFERER referer))
      (when proxy  (_ hnd CURLOPT_PROXY proxy))
      (when interface (_ hnd CURLOPT_INTERFACE interface)))))



;;       ((progress-bar "#|progress-bar" #f)
;;        (anyauth "anyauth" #f)
;;        (basic "basic" #f)
;;        (buffer "buffer" #f)
;;        (cacert "cacert=s")
;;        (capath "capath=s")
;;        (cert-type "cert-type=s") 
;;        (ciphers "ciphers=s")
;;        (compressed "compressed"   #f)
;;        (connect-timeout "connect-timeout=s" )
;;        (create-dirs "create-dirs" #f)
;;        (crlf "crlf" #f)
;;        (data-ascii "data-ascii" #f)
;;        (data-binary "data-binary" #f)
;;        (data-urlencode "data-urlencode=s" )
;;        (digest "digest" #f)
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
;;        (ignore-content-length "ignore-content-length" #f)
;;        (interface "interface=s" )
;;        (keepalive "keepalive" #f)
;;        (keepalive-time "keepalive-time=s" )
;;        (key "key=s" )
;;        (key-type "key-type=s" )
;;        (krb "krb=s" )
;;        (libcurl "libcurl=s" )
;;        (limit-rate "limit-rate=s" )
;;        (local-port "local-port=s" )
;;        (location-trusted "location-trusted" #f)
;;        (max-filesize "max-filesize=s" )
;;        (max-redirs "max-redirs=s" )
;;        (negotiate "negotiate" #f)
;;        (netrc-optional "netrc-optional" #f)
;;        (no-eprt "no-eprt" #f)
;;        (no-epsv "no-epsv" #f)
;;        (no-keepalive "no-keepalive" #f)
;;        (no-sessionid "no-sessionid" #f)
;;        (noproxy "noproxy=s")
;;        (ntlm "ntlm" #f)
;;        (pass "pass=s" )
;;        (post301 "post301" #f)
;;        (post302 "post302" #f)
;;        (proxy-anyauth "proxy-anyauth" #f)
;;        (proxy-basic "proxy-basic" #f)
;;        (proxy-digest "proxy-digest" #f)
;;        (proxy-negotiate "proxy-negotiate" #f)
;;        (proxy-ntlm "proxy-ntlm" #f)
;;        (proxy1.0 "proxy1.0=s" )
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
;;        (stderr "stderr=s" )
;;        (tcp-nodelay "tcp-nodelay" #f)
;;        (trace "trace=s" )
;;        (trace-ascii "trace-ascii=s" )
;;        (trace-time "trace-time" #f)
;;        (url "url=s" )
;;        (http1.0 "0|http1.0" #f)
;;        (tlsv1 "1|tlsv1" #f)
;;        (sslv2 "2|sslv2" #f)
;;        (sslv3 "3|sslv3" #f)
;;        (ipv4 "4|ipv4" #f)
;;        (ipv6 "6|ipv6" #f)
;;        (user-agent "A|user-agent=s" )
;;        (use-ascii "B|use-ascii" #f)
;;        (continue-at "C|continue-at=s" )
;;        (dump-header "D|dump-header=s" )
;;        (cert "E|cert=s" )
;;        (form "F|form=s" )
;;        (get "G|get" #f)
;;        (header "H|header=s" )
;;        (head "I|head" #f)
;;        (config "K|config=s" )
;;        (location "L|location" #f)
;;        (manual "M|manual" #f)
;;        (no-buffer "N|no-buffer" #f)
;;        (remote-name "O|remote-name" #f)
;;        (ftp-port "P|ftp-port=s" )
;;        (quote "Q|quote=s" )
;;        (remote-time "R|remote-time=s" )
;;        (show-error "S|show-error" #f)
;;        (upload-file "T|upload-file=s" )
;;        (proxy-user "U|proxy-user=s" )
;;        (version "V|version" #f)
;;        (request "X|request=s" )
;;        (speed-limit "Y|speed-limit=s" )
;;        (append "a|append" #f)
;;        (cookie "b|cookie=s" )
;;        (cookie-jar "c|cookie-jar=s" )
;;        (data "d|data=s" )
;;        (referer "e|referer=s" )
;;        (fail "f|fail" #f)
;;        (globoff "g|globoff" #f)
;;        (help "h|help" #f)
;;        (include "i|include" #f)
;;        (junk-session-cookies "j|junk-session-cookies" #f)
;;        (insecure "k|insecure" #f)
;;        (list-only "l|list-only" #f)
;;        (max-time "m|max-time=s" )
;;        (netrc "n|netrc" #f)
;;        (output "o|output=s" )
;;        (proxytunnel "p|proxytunnel" #f)
;;        (q "q" #f)
;;        (range "r|range=s" )
;;        (silent "s|silent" #f)
;;        (telnet-option "t|telnet-option=s" )
;;        (user "u|user=s" )
;;        (verbose "v|verbose" #f)
;;        (write-out "w|write-out=s" )
;;        (proxy "x|proxy=s" )
;;        (speed-time "y|speed-time=s" )
;;        (time-cond "z|time-cond=s"))
;;     ()))


(define (curl url . optstr)
  ((make <curl> :url url :options (car optstr))))


;; Common
(define (http-common hnd)
  (curl-easy-setopt hnd CURLOPT_USERAGENT 
		    (string-append "Gauche " (gauche-version) "/libcurl " (curl-version)))
  (curl-easy-setopt hnd CURLOPT_AUTOREFERER 1)
  (curl-easy-setopt hnd CURLOPT_ENCODING )
  (curl-easy-setopt hnd CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_NONE)
  (curl-easy-setopt hnd CURLOPT_HTTPHEADER (list->curl-slist head-ls)))

;; GET
(define (http-get url str . head-ls)
  (let1 hnd (curl-easy-init)
    (curl-easy-setopt hnd CURLOPT_URL url)
    (curl-easy-setopt hnd CURLOPT_HTTPGET 1)
    (curl-easy-perform hnd)
    (values 
     (curl-easy-getinfo hnd CURLINFO_RESPONSE_CODE))))


;; POST
(define (http-post url str . head-ls)
  (let1 hnd (curl-easy-init)
    (curl-easy-setopt hnd CURLOPT_URL url)
    (curl-easy-setopt hnd CURLOPT_CUSTOMREQUEST "POST")
    (curl-easy-setopt hnd CURLOPT_POSTFIELDS str)
    (curl-easy-setopt hnd CURLOPT_POSTFIELDSIZE (string-size str))
    (curl-easy-setopt hnd CURLOPT_HTTPHEADER s2)
    (curl-easy-perform hnd)
    (values 
     (curl-easy-getinfo hnd CURLINFO_RESPONSE_CODE))))

;; PUT

;; DELETE


;; Epilogue
(provide "curl")

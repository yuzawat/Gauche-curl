;;;
;;; Test curl
;;;

(use gauche.test)
(use gauche.interactive)

(test-start "curl")
(use curl)
(test-module 'curl)

;; The following is a dummy test code.
;; Replace it for your tests.
(test* "test-curl" "curl is working"
       (test-curl))

(test* "curl-version" #t
       (regmatch? (#/^libcurl/  (curl-version))))

(describe <curl-base>)

(test* "curl-easy-init" #t
       (is-a? (curl-easy-init) <curl-base>))

(test* "curl-easy-cleanup" #t
       (eq? (undefined) (curl-easy-cleanup (curl-easy-init) )))

(test* "curl-easy-reset" #t
       (eq? (undefined) (curl-easy-reset (curl-easy-init) )))

(define c (curl-easy-init))

(test* "curl-easy-escape" "This%20is%20a%20test%2E"
       (curl-easy-escape c "This is a test." 0))

(test* "curl-easy-unescape" "This is a test."
       (curl-easy-unescape c "This%20is%20a%20test%2E" 0 0))

(test* "curl-easy-setopt " 0
  (curl-easy-setopt c CURLOPT_INFILESIZE_LARGE (- CURLOPTTYPE_OFF_T 1)))

(test* "curl-easy-setopt (set URL)" 0
       (curl-easy-setopt c CURLOPT_URL "http://bitworking.org/projects/apptestsite/app.cgi/service/;service_document"))

(test* "curl-easy-setopt (set timeout)" 0
        (curl-easy-setopt c CURLOPT_TIMEOUT 10))

(test* "curl-easy-setopt (set proxy off)" 0
        (curl-easy-setopt c CURLOPT_PROXY #f))

(test* "curl-easy-setopt (set verbose)" 0
        (curl-easy-setopt c CURLOPT_VERBOSE 1))

(curl-bind-input-port c)
(curl-bind-output-port c)

(test* "curl-easy-perform" 0
       (with-output-to-string 
	 (lambda () (curl-easy-perform c))))

(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo c CURLINFO_RESPONSE_CODE))

(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo c CURLINFO_CONTENT_TYPE))

(test* "curl-easy-duphandle" #t
       (is-a? (curl-easy-duphandle c) <curl-base>))

(print CURLE_OK)
(print CURLE_UNSUPPORTED_PROTOCOL)
(print CURLE_FAILED_INIT)
(print CURLE_URL_MALFORMAT)
(print CURLE_COULDNT_RESOLVE_PROXY)
(print CURLE_COULDNT_RESOLVE_HOST)
(print CURLE_COULDNT_CONNECT)
(print CURLE_FTP_WEIRD_SERVER_REPLY)
(print CURLE_REMOTE_ACCESS_DENIED)
(print CURLE_FTP_WEIRD_PASS_REPLY)
(print CURLE_FTP_WEIRD_PASV_REPLY)
(print CURLE_FTP_WEIRD_227_FORMAT)
(print CURLE_FTP_CANT_GET_HOST)
(print CURLE_FTP_COULDNT_SET_TYPE)
(print CURLE_PARTIAL_FILE)
(print CURLE_FTP_COULDNT_RETR_FILE)
(print CURLE_QUOTE_ERROR)
(print CURLE_HTTP_RETURNED_ERROR)
(print CURLE_WRITE_ERROR)
(print CURLE_UPLOAD_FAILED)
(print CURLE_READ_ERROR)
(print CURLE_OUT_OF_MEMORY)
(print CURLE_OPERATION_TIMEDOUT)
(print CURLE_FTP_PORT_FAILED)
(print CURLE_FTP_COULDNT_USE_REST)
(print CURLE_RANGE_ERROR)
(print CURLE_HTTP_POST_ERROR)
(print CURLE_SSL_CONNECT_ERROR)
(print CURLE_BAD_DOWNLOAD_RESUME)
(print CURLE_FILE_COULDNT_READ_FILE)
(print CURLE_LDAP_CANNOT_BIND)
(print CURLE_LDAP_SEARCH_FAILED)
(print CURLE_FUNCTION_NOT_FOUND)
(print CURLE_ABORTED_BY_CALLBACK)
(print CURLE_BAD_FUNCTION_ARGUMENT)
(print CURLE_INTERFACE_FAILED)
(print CURLE_TOO_MANY_REDIRECTS)
(print CURLE_UNKNOWN_TELNET_OPTION)
(print CURLE_TELNET_OPTION_SYNTAX)
(print CURLE_PEER_FAILED_VERIFICATION)
(print CURLE_GOT_NOTHING)
(print CURLE_SSL_ENGINE_NOTFOUND)
(print CURLE_SSL_ENGINE_SETFAILED)
(print CURLE_SEND_ERROR)
(print CURLE_RECV_ERROR)
(print CURLE_SSL_CERTPROBLEM)
(print CURLE_SSL_CIPHER)
(print CURLE_SSL_CACERT)
(print CURLE_BAD_CONTENT_ENCODING)
(print CURLE_LDAP_INVALID_URL)
(print CURLE_FILESIZE_EXCEEDED)
(print CURLE_USE_SSL_FAILED)
(print CURLE_SEND_FAIL_REWIND)
(print CURLE_SSL_ENGINE_INITFAILED)
(print CURLE_LOGIN_DENIED)
(print CURLE_TFTP_NOTFOUND)
(print CURLE_TFTP_PERM)
(print CURLE_REMOTE_DISK_FULL)
(print CURLE_TFTP_ILLEGAL)
(print CURLE_TFTP_UNKNOWNID)
(print CURLE_REMOTE_FILE_EXISTS)
(print CURLE_TFTP_NOSUCHUSER)
(print CURLE_CONV_FAILED)
(print CURLE_CONV_REQD)
(print CURLE_SSL_CACERT_BADFILE)
(print CURLE_REMOTE_FILE_NOT_FOUND)
(print CURLE_SSH)
(print CURLE_SSL_SHUTDOWN_FAILED)
(print CURLE_AGAIN)
(print CURL_LAST)

(print CURLOPT_WRITEDATA)
(print CURLOPT_WRITEFUNCTION)
(print CURLOPT_READDATA)
(print CURLOPT_READFUNCTION)
(print CURLOPT_SEEKDATA)
(print CURLOPT_SEEKFUNCTION)
(print CURLOPT_INFILESIZE_LARGE)
(print CURLOPT_URL)
(print CURLOPT_PROXY)
(print CURLOPT_NOPROGRESS)
(print CURLOPT_HEADER)
(print CURLOPT_FAILONERROR)
(print CURLOPT_UPLOAD)
(print CURLOPT_DIRLISTONLY)
(print CURLOPT_APPEND)
(print CURLOPT_NETRC)
(print CURLOPT_FOLLOWLOCATION)
(print CURLOPT_UNRESTRICTED_AUTH)
(print CURLOPT_TRANSFERTEXT)
(print CURLOPT_USERPWD)
(print CURLOPT_PROXYUSERPWD)
(print CURLOPT_RANGE)
(print CURLOPT_ERRORBUFFER)
(print CURLOPT_TIMEOUT)
(print CURLOPT_REFERER)
(print CURLOPT_AUTOREFERER)
(print CURLOPT_USERAGENT)
(print CURLOPT_FTPPORT)
(print CURLOPT_LOW_SPEED_LIMIT)
(print CURLOPT_LOW_SPEED_TIME)
(print CURLOPT_MAX_SEND_SPEED_LARGE)
(print CURLOPT_MAX_RECV_SPEED_LARGE)
(print CURLOPT_RESUME_FROM_LARGE)
(print CURLOPT_COOKIE)
(print CURLOPT_HTTPHEADER)
(print CURLOPT_SSLCERT)
(print CURLOPT_SSLCERTTYPE)
(print CURLOPT_SSLKEY)
(print CURLOPT_SSLKEYTYPE)
(print CURLOPT_KEYPASSWD)
(print CURLOPT_SSH_PRIVATE_KEYFILE)
(print CURLOPT_SSH_PUBLIC_KEYFILE)
(print CURLOPT_SSH_HOST_PUBLIC_KEY_MD5)
(print CURLOPT_SSL_VERIFYHOST)
(print CURLOPT_MAXREDIRS)
(print CURLOPT_CRLF)
(print CURLOPT_QUOTE)
(print CURLOPT_POSTQUOTE)
(print CURLOPT_PREQUOTE)
(print CURLOPT_WRITEHEADER)
(print CURLOPT_COOKIEFILE)
(print CURLOPT_COOKIESESSION)
(print CURLOPT_SSLVERSION)
(print CURLOPT_TIMECONDITION)
(print CURLOPT_TIMEVALUE)
(print CURLOPT_CUSTOMREQUEST)
(print CURLOPT_STDERR)
(print CURLOPT_HTTPPROXYTUNNEL)
(print CURLOPT_INTERFACE)
(print CURLOPT_KRBLEVEL)
(print CURLOPT_TELNETOPTIONS)
(print CURLOPT_RANDOM_FILE)
(print CURLOPT_EGDSOCKET)
(print CURLOPT_CONNECTTIMEOUT)
(print CURLOPT_DEBUGFUNCTION)
(print CURLOPT_DEBUGDATA)
(print CURLOPT_VERBOSE)
(print CURLOPT_ENCODING)
(print CURLOPT_FTP_CREATE_MISSING_DIRS)
(print CURLOPT_IPRESOLVE)
(print CURLOPT_FTP_ACCOUNT)
(print CURLOPT_IGNORE_CONTENT_LENGTH)
(print CURLOPT_FTP_SKIP_PASV_IP)
(print CURLOPT_FTP_FILEMETHOD)
(print CURLOPT_FTP_ALTERNATIVE_TO_USER)
(print CURLOPT_SSL_SESSIONID_CACHE)
(print CURLOPT_SOCKOPTFUNCTION)
(print CURLOPT_SOCKOPTDATA)

;; epilogue
(test-end)






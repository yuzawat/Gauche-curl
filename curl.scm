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
  (export 
   <curl-base>
   test-curl ;; dummy
   curl-easy-init
   curl-easy-cleanup
   curl-easy-setopt
   curl-easy-perform
   curl-easy-reset
   curl-easy-duphandle
   curl-version
   curl-version-info
   curl-easy-getinfo
   curl-bind-input-port
   curl-bind-output-port
   curl-easy-escape
   curl-easy-unescape

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
CURL_LAST

CURLOPT_WRITEDATA
CURLOPT_WRITEFUNCTION
CURLOPT_READDATA
CURLOPT_READFUNCTION
CURLOPT_SEEKDATA
CURLOPT_SEEKFUNCTION
CURLOPT_INFILESIZE_LARGE
CURLOPT_URL
CURLOPT_PROXY
CURLOPT_NOPROGRESS
CURLOPT_HEADER
CURLOPT_FAILONERROR
CURLOPT_UPLOAD
CURLOPT_DIRLISTONLY
CURLOPT_APPEND
CURLOPT_NETRC
CURLOPT_FOLLOWLOCATION
CURLOPT_UNRESTRICTED_AUTH
CURLOPT_TRANSFERTEXT
CURLOPT_USERPWD
CURLOPT_PROXYUSERPWD
CURLOPT_RANGE
CURLOPT_ERRORBUFFER
CURLOPT_TIMEOUT
CURLOPT_REFERER
CURLOPT_AUTOREFERER
CURLOPT_USERAGENT
CURLOPT_FTPPORT
CURLOPT_LOW_SPEED_LIMIT
CURLOPT_LOW_SPEED_TIME
CURLOPT_MAX_SEND_SPEED_LARGE
CURLOPT_MAX_RECV_SPEED_LARGE
CURLOPT_RESUME_FROM_LARGE
CURLOPT_COOKIE
CURLOPT_HTTPHEADER
CURLOPT_SSLCERT
CURLOPT_SSLCERTTYPE
CURLOPT_SSLKEY
CURLOPT_SSLKEYTYPE
CURLOPT_KEYPASSWD
CURLOPT_SSH_PRIVATE_KEYFILE
CURLOPT_SSH_PUBLIC_KEYFILE
CURLOPT_SSH_HOST_PUBLIC_KEY_MD5
CURLOPT_SSL_VERIFYHOST
CURLOPT_MAXREDIRS
CURLOPT_CRLF
CURLOPT_QUOTE
CURLOPT_POSTQUOTE
CURLOPT_PREQUOTE
CURLOPT_WRITEHEADER
CURLOPT_COOKIEFILE
CURLOPT_COOKIESESSION
CURLOPT_SSLVERSION
CURLOPT_TIMECONDITION
CURLOPT_TIMEVALUE
CURLOPT_CUSTOMREQUEST
CURLOPT_STDERR
CURLOPT_HTTPPROXYTUNNEL
CURLOPT_INTERFACE
CURLOPT_KRBLEVEL
CURLOPT_TELNETOPTIONS
CURLOPT_RANDOM_FILE
CURLOPT_EGDSOCKET
CURLOPT_CONNECTTIMEOUT
CURLOPT_DEBUGFUNCTION
CURLOPT_DEBUGDATA
CURLOPT_VERBOSE
CURLOPT_ENCODING
CURLOPT_FTP_CREATE_MISSING_DIRS
CURLOPT_IPRESOLVE
CURLOPT_FTP_ACCOUNT
CURLOPT_IGNORE_CONTENT_LENGTH
CURLOPT_FTP_SKIP_PASV_IP
CURLOPT_FTP_FILEMETHOD
CURLOPT_FTP_ALTERNATIVE_TO_USER
CURLOPT_SSL_SESSIONID_CACHE
CURLOPT_SOCKOPTFUNCTION
CURLOPT_SOCKOPTDATA

CURLOPTTYPE_OFF_T

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

CURLVERSION_NOW

   )
  )
(select-module curl)

;; Loads extension
(dynamic-load "curl")

;;
;; Put your Scheme definitions here
;;
(define (options args)
  (let-args args
      ((progress-bar "#|progress-bar" #f)
       (anyauth "anyauth" #f)
       (basic "basic" #f)
       (buffer "buffer" #f)
       (cacert "cacert=s")
       (capath "capath=s")
       (cert-type "cert-type=s") 
       (ciphers "ciphers=s")
       (compressed "compressed"   #f)
       (connect-timeout "connect-timeout=s" )
       (create-dirs "create-dirs" #f)
       (crlf "crlf" #f)
       (data-ascii "data-ascii" #f)
       (data-binary "data-binary" #f)
       (data-urlencode "data-urlencode=s" )
       (digest "digest" #f)
       (disable-eprt "disable-eprt" #f)
       (disable-epsv "disable-epsv" #f)
       (egd-file "egd-file=s" )
       (engine "engine=s" )
       (environment "environment" #f)
       (eprt "eprt" #f)
       (epsv "epsv" #f)
       (form-string "form-string=s" )
       (ftp-account "ftp-account=s" )
       (ftp-alternative-to-user "ftp-alternative-to-user=s" )
       (ftp-create-dirs "ftp-create-dirs" #f)
       (ftp-method "ftp-method=s" )
       (ftp-pasv "ftp-pasv" #f)
       (ftp-skip-pasv-ip "ftp-skip-pasv-ip" #f)
       (ftp-ssl "ftp-ssl" #f)
       (ftp-ssl-ccc "ftp-ssl-ccc" #f)
       (ftp-ssl-ccc-mode "ftp-ssl-ccc-mode=s" )
       (ftp-ssl-control "ftp-ssl-control" #f)
       (ftp-ssl-reqd "ftp-ssl-reqd" #f)
       (hostpubmd5 "hostpubmd5=s" )
       (ignore-content-length "ignore-content-length" #f)
       (interface "interface=s" )
       (keepalive "keepalive" #f)
       (keepalive-time "keepalive-time=s" )
       (key "key=s" )
       (key-type "key-type=s" )
       (krb "krb=s" )
       (libcurl "libcurl=s" )
       (limit-rate "limit-rate=s" )
       (local-port "local-port=s" )
       (location-trusted "location-trusted" #f)
       (max-filesize "max-filesize=s" )
       (max-redirs "max-redirs=s" )
       (negotiate "negotiate" #f)
       (netrc-optional "netrc-optional" #f)
       (no-eprt "no-eprt" #f)
       (no-epsv "no-epsv" #f)
       (no-keepalive "no-keepalive" #f)
       (no-sessionid "no-sessionid" #f)
       (noproxy "noproxy=s")
       (ntlm "ntlm" #f)
       (pass "pass=s" )
       (post301 "post301" #f)
       (post302 "post302" #f)
       (proxy-anyauth "proxy-anyauth" #f)
       (proxy-basic "proxy-basic" #f)
       (proxy-digest "proxy-digest" #f)
       (proxy-negotiate "proxy-negotiate" #f)
       (proxy-ntlm "proxy-ntlm" #f)
       (proxy1.0 "proxy1.0=s" )
       (pubkey "pubkey=s" )
       (random-file "random-file=s" )
       (raw "raw" #f)
       (remote-name-all "remote-name-all" #f)
       (retry "retry=s" )
       (retry-delay "retry-delay=s" )
       (retry-max-time "retry-max-time=s" )
       (sessionid "sessionid" #f)
       (socks4 "socks4=s" )
       (socks4a "socks4a=s" )
       (socks5 "socks5=s" )
       (socks5-gssapi-nec "socks5-gssapi-nec" #f)
       (socks5-gssapi-service "socks5-gssapi-service=s" )
       (socks5-hostname "socks5-hostname=s" )
       (stderr "stderr=s" )
       (tcp-nodelay "tcp-nodelay" #f)
       (trace "trace=s" )
       (trace-ascii "trace-ascii=s" )
       (trace-time "trace-time" #f)
       (url "url=s" )
       (http1.0 "0|http1.0" #f)
       (tlsv1 "1|tlsv1" #f)
       (sslv2 "2|sslv2" #f)
       (sslv3 "3|sslv3" #f)
       (ipv4 "4|ipv4" #f)
       (ipv6 "6|ipv6" #f)
       (user-agent "A|user-agent=s" )
       (use-ascii "B|use-ascii" #f)
       (continue-at "C|continue-at=s" )
       (dump-header "D|dump-header=s" )
       (cert "E|cert=s" )
       (form "F|form=s" )
       (get "G|get" #f)
       (header "H|header=s" )
       (head "I|head" #f)
       (config "K|config=s" )
       (location "L|location" #f)
       (manual "M|manual" #f)
       (no-buffer "N|no-buffer" #f)
       (remote-name "O|remote-name" #f)
       (ftp-port "P|ftp-port=s" )
       (quote "Q|quote=s" )
       (remote-time "R|remote-time=s" )
       (show-error "S|show-error" #f)
       (upload-file "T|upload-file=s" )
       (proxy-user "U|proxy-user=s" )
       (version "V|version" #f)
       (request "X|request=s" )
       (speed-limit "Y|speed-limit=s" )
       (append "a|append" #f)
       (cookie "b|cookie=s" )
       (cookie-jar "c|cookie-jar=s" )
       (data "d|data=s" )
       (referer "e|referer=s" )
       (fail "f|fail" #f)
       (globoff "g|globoff" #f)
       (help "h|help" #f)
       (include "i|include" #f)
       (junk-session-cookies "j|junk-session-cookies" #f)
       (insecure "k|insecure" #f)
       (list-only "l|list-only" #f)
       (max-time "m|max-time=s" )
       (netrc "n|netrc" #f)
       (output "o|output=s" )
       (proxytunnel "p|proxytunnel" #f)
       (q "q" #f)
       (range "r|range=s" )
       (silent "s|silent" #f)
       (telnet-option "t|telnet-option=s" )
       (user "u|user=s" )
       (verbose "v|verbose" #f)
       (write-out "w|write-out=s" )
       (proxy "x|proxy=s" )
       (speed-time "y|speed-time=s" )
       (time-cond "z|time-cond=s"))
    ()))

;; Epilogue
(provide "curl")

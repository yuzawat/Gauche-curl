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

(test* "curl-version-info: version is over 7.18.x" #t
       (regmatch? (#/7\.1[89]\./ (cdr (assoc "version" (curl-version-info))))))

(test* "curl-version-info: support http" #t
       (regmatch? (#/\bhttp\b/ (cdr (assoc "protocols" (curl-version-info))))))

(test* "curl-version-info: support https" #t
       (regmatch? (#/\bhttps\b/ (cdr (assoc "protocols" (curl-version-info))))))

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
       (curl-easy-setopt c CURLOPT_URL "http://www.google.com/"))

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
       (curl-easy-getinfo c CURLINFO_EFFECTIVE_URL))

(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo c CURLINFO_CONTENT_TYPE))

(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo c CURLINFO_COOKIELIST))

(test* "curl-easy-duphandle" #t
       (is-a? (curl-easy-duphandle c) <curl-base>))

(test* "curl-easy-strerror" #t
        (curl-easy-strerror 0))

(curl-easy-cleanup c)

(define post-string "email=example@example.tld&password=example&type=regular&body=This_is_a_test3&private=1&format=markdown")
(define c (curl-easy-init))

(define s (curl-slist-init))

(test* "curl-slist-init" #t
       (is-a? (curl-slist-init) <curl-slist>))
(test* "curl-slist-append 1" #t
       (is-a? (curl-slist-append s "Content-Length: 103") <curl-slist>))
(test* "curl-slist-append 2" #t
       (is-a? (curl-slist-append s "Content-Type: application/x-www-form-urlencoded") <curl-slist>))
(test* "curl-slist-append 3" #t
       (is-a? (curl-slist-append s "X-hoge0: hoge") <curl-slist>))
(test* "curl-slist-append 4" #t
       (is-a?  (curl-slist-append s "X-gere0: gere") <curl-slist>))

(curl-easy-setopt c CURLOPT_URL "http://www.tumblr.com/api/write/")
(curl-easy-setopt c CURLOPT_VERBOSE 1)
(curl-easy-setopt c CURLOPT_TIMEOUT 10)
(curl-easy-setopt c CURLOPT_CUSTOMREQUEST "POST")
#;(curl-easy-setopt c CURLOPT_PROXY "http://192.168.0.1:8080")
#;(curl-easy-setopt c CURLOPT_POSTFIELDS post-string)
;(curl-easy-setopt c CURLOPT_POSTFIELDSIZE 101)
(curl-easy-setopt c CURLOPT_POSTFIELDSIZE_LARGE (- CURLOPTTYPE_OFF_T 1))
;(curl-easy-setopt c CURLOPT_INFILESIZE 256)
(curl-easy-setopt c CURLOPT_UPLOAD 0)
(curl-easy-setopt c CURLOPT_HTTPHEADER s)
(curl-bind-input-port c)
(curl-bind-output-port c)

(test* "post" ""
       (with-output-to-string 
	   (lambda () 
	     (with-input-from-string post-string 
	       (lambda () (curl-easy-perform c))))))

(test* "post result" 201
       (curl-easy-getinfo c CURLINFO_RESPONSE_CODE))

;; epilogue
(test-end)

;;; -*- coding: utf-8; mode: scheme -*-
;;; Test curl
;;;

(use gauche.test)
(use gauche.interactive)

(test-start "curl")
(use curl)
#;(test-module 'curl)

; global constants init
(test* "curl-global-init" 0
       (curl-global-init CURL_GLOBAL_ALL))

; curl version
(test-section "curl version check")
(test* "curl-version" #t
       (regmatch? (#/^libcurl/  (curl-version))))
(test* "curl-version-info: version is over 7.18.x" #t
       (regmatch? (#/7\.1[89]\./ (cdr (assoc "version" (curl-version-info))))))
(test* "curl-version-info: support http" #t
       (regmatch? (#/\bhttp\b/ (cdr (assoc "protocols" (curl-version-info))))))
(test* "curl-version-info: support https" #t
       (regmatch? (#/\bhttps\b/ (cdr (assoc "protocols" (curl-version-info))))))
(describe <curl-base>)


;; basic
(test-section "curl basic handler")
(test* "curl-easy-init" #t
       (is-a? (curl-easy-init) <curl-base>))
(test* "curl-easy-cleanup" #t
       (eq? (undefined) (curl-easy-cleanup (curl-easy-init) )))
(test* "curl-easy-reset" #t
       (eq? (undefined) (curl-easy-reset (curl-easy-init) )))
(define hnd (curl-easy-init))
(test* "curl-easy-duphandle" #t
       (is-a? (curl-easy-duphandle hnd) <curl-base>))
(curl-easy-cleanup hnd)


;; misc utils
(test-section "curl misc utils")
(define hnd (curl-easy-init))
(test* "curl-easy-escape" "This%20is%20a%20test%2E"
       (curl-easy-escape hnd "This is a test." 0))
(test* "curl-easy-unescape" "This is a test."
       (curl-easy-unescape hnd "This%20is%20a%20test%2E" 0 0))
(curl-easy-cleanup hnd)

(test-section "HTTP GET")
;; HTTP GET
(define hnd (curl-easy-init))
(test* "curl-easy-setopt (set URL)" 0
       (curl-easy-setopt hnd CURLOPT_URL "http://www.google.com/"))
#;(test* "curl-easy-setopt (set URL)" 0
       (curl-easy-setopt hnd CURLOPT_URL "http://localhost:8080/hello"))

;;  common
(test* "curl-easy-setopt (set timeout)" 0
        (curl-easy-setopt hnd CURLOPT_TIMEOUT 10))
(test* "curl-easy-setopt (set proxy off)" 0
        (curl-easy-setopt hnd CURLOPT_PROXY ""))
(test* "curl-easy-setopt (set verbose)" 0
        (curl-easy-setopt hnd CURLOPT_VERBOSE 0))
(test* "curl-easy-setopt (set follow location)" 0
       (curl-easy-setopt hnd CURLOPT_FOLLOWLOCATION 1))
(test* "curl-easy-setopt (set encoding)" 0
       (curl-easy-setopt hnd CURLOPT_ENCODING ""))
(test* "curl-easy-setopt (set auto referer)" 0
       (curl-easy-setopt hnd CURLOPT_AUTOREFERER 1))
(test* "curl-easy-setopt (set user agent)" 0
       (curl-easy-setopt hnd CURLOPT_USERAGENT 
			 (string-append "Gauche " (gauche-version) " " (curl-version))))
(test* "curl-easy-setopt (set http version)" 0
       (curl-easy-setopt hnd CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_NONE))
(test* "curl-easy-setopt (set body include no header)" 0
       (curl-easy-setopt hnd CURLOPT_HEADER 0))

;; #;(curl-bind-input-port c)
#;(curl-bind-output-port hnd)
(curl-open-output-port hnd)
;(curl-open-header-port hnd "hoge-head.txt")

(define body (with-output-to-string
	 (lambda () (curl-easy-perform hnd))))

;; response
(test* "curl-easy-getinfo (response code)" #t
       (curl-easy-getinfo hnd CURLINFO_RESPONSE_CODE))
(test* "curl-easy-getinfo (effective url)" #t
       (curl-easy-getinfo hnd CURLINFO_EFFECTIVE_URL))
(test* "curl-easy-getinfo (content type)" #t
       (curl-easy-getinfo hnd CURLINFO_CONTENT_TYPE))
#;(test* "curl-easy-getinfo (cookie list)" #t
       (curl-easy-getinfo hnd CURLINFO_COOKIELIST))
(test* "curl-easy-strerror" #t
        (curl-easy-strerror 0))
(curl-easy-cleanup hnd)


(test* "curl-global-cleanup" #t
       (eq? (undefined) (curl-global-cleanup)))

(test-end)
(display body)
(exit)

;; HTTP POST
(test-section "HTTP POST")
#;(define post-string "email=example@example.tld&password=example&type=regular&body=This%20is%20a%20test3&private=1&format=markdown")
(define post-string "email=yuzawata@gmail.com&password=B'dikkat&type=regular&body=This%20is%20a%20test3&private=1&format=markdown")
(define hnd (curl-easy-init))
(curl-easy-setopt hnd CURLOPT_URL "http://www.tumblr.com/api/write/")
(test* "curl-easy-setopt (set custom request)" 0
       (curl-easy-setopt hnd CURLOPT_CUSTOMREQUEST "POST"))
(test* "curl-easy-setopt (set post field)" 0
       (curl-easy-setopt hnd CURLOPT_POSTFIELDS post-string))
(test* "curl-easy-setopt (set post field size)" 0
       (curl-easy-setopt hnd CURLOPT_POSTFIELDSIZE (string-size post-string)))

;;  common
(test* "curl-easy-setopt " 0
       (curl-easy-setopt hnd CURLOPT_INFILESIZE_LARGE (- CURLOPTTYPE_OFF_T 1)))
(curl-easy-setopt hnd CURLOPT_TIMEOUT 10)
(curl-easy-setopt hnd CURLOPT_PROXY "")
(curl-easy-setopt hnd CURLOPT_VERBOSE 1)
(curl-easy-setopt hnd CURLOPT_FOLLOWLOCATION 1)
(curl-easy-setopt hnd CURLOPT_ENCODING "")
(curl-easy-setopt hnd CURLOPT_AUTOREFERER 1)
(curl-easy-setopt hnd CURLOPT_USERAGENT 
		  (string-append "Gauche " (gauche-version) " " (curl-version)))
(curl-easy-setopt hnd CURLOPT_HTTP_VERSION CURL_HTTP_VERSION_NONE)

(test* "curl-easy-setopt (set header)" 0
       (curl-easy-setopt hnd CURLOPT_HTTPHEADER 
			 (list->curl-slist (list "X-hoge0: hoge" "X-hoge1: hoge" "X-hoge2: hoge"))))

(curl-bind-output-port hnd)
(curl-bind-header-port hnd)

(test* "post" ""
       (with-output-to-string 
	   (lambda () (curl-easy-perform hnd))))

;; response
(test* "curl-easy-getinfo (response code)" #t
       (curl-easy-getinfo hnd CURLINFO_RESPONSE_CODE))
(test* "curl-easy-getinfo (effective url)" #t
       (curl-easy-getinfo hnd CURLINFO_EFFECTIVE_URL))
(test* "curl-easy-getinfo (content type)" #t
       (curl-easy-getinfo hnd CURLINFO_CONTENT_TYPE))
#;(test* "curl-easy-getinfo (cookie list)" #t
       (curl-easy-getinfo hnd CURLINFO_COOKIELIST))
(test* "curl-easy-strerror" #t
        (curl-easy-strerror 0))

;; HTTP PUT
(test-section "HTTP PUT")

;; HTTP DELETE
(test-section "HTTP DELETE")


(test* "curl-global-cleanup" #t
       (eq? (undefined) (curl-global-cleanup)))
;; epilogue
(test-end)

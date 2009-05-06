;;;
;;; Test curl
;;;

(use gauche.test)
(use gauche.interactive)

(test-start "curl")
(use curl)
#;(test-module 'curl)

;; The following is a dummy test code.
;; Replace it for your tests.
(test* "test-curl" "curl is working"
       (test-curl))


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

;;  common
(test* "curl-easy-setopt (set timeout)" 0
        (curl-easy-setopt hnd CURLOPT_TIMEOUT 10))
(test* "curl-easy-setopt (set proxy off)" 0
        (curl-easy-setopt hnd CURLOPT_PROXY #f))
(test* "curl-easy-setopt (set verbose)" 0
        (curl-easy-setopt hnd CURLOPT_VERBOSE 1))

#;(curl-bind-input-port c)
(curl-bind-output-port hnd)

(test* "curl-easy-perform" 0
       (with-output-to-string 
	 (lambda () (curl-easy-perform hnd))))

;; response
(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_RESPONSE_CODE))
(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_EFFECTIVE_URL))
(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_CONTENT_TYPE))
#;(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_COOKIELIST))
(test* "curl-easy-strerror" #t
        (curl-easy-strerror 0))
(curl-easy-cleanup hnd)


;; HTTP POST
(test-section "HTTP POST")
(define post-string "email=example@example.tld&password=example&type=regular&body=This%20is%20a%20test3&private=1&format=markdown")
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
(curl-easy-setopt hnd CURLOPT_PROXY #f)
(curl-easy-setopt hnd CURLOPT_VERBOSE 1)

(test* "curl-easy-setopt (set header)" 0
       (curl-easy-setopt hnd CURLOPT_HTTPHEADER 
			 (list->curl-slist (list "X-hoge0: hoge" "X-hoge1: hoge" "X-hoge2: hoge"))))

(curl-bind-output-port hnd)

(test* "post" ""
       (with-output-to-string 
	   (lambda () (curl-easy-perform hnd))))

;; response
(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_RESPONSE_CODE))
(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_EFFECTIVE_URL))
(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_CONTENT_TYPE))
#;(test* "curl-easy-getinfo" #t
       (curl-easy-getinfo hnd CURLINFO_COOKIELIST))
(test* "curl-easy-strerror" #t
        (curl-easy-strerror 0))

;; HTTP PUT
(test-section "HTTP PUT")

;; HTTP DELETE
(test-section "HTTP DELETE")

;; epilogue
(test-end)

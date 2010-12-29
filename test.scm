;;; -*- coding: utf-8; mode: scheme -*-
;;; Test curl
;;;
(use gauche.test)
(use gauche.version)

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
(test* "curl-version-info: version is over 7.x.x" #t
       (regmatch? (#/7\.\d+\./ (cdr (assoc "version" (curl-version-info))))))
(test* "curl-version-info: support http" #t
       (regmatch? (#/\bhttp\b/ (cdr (assoc "protocols" (curl-version-info))))))

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
(if (version<=? "7.21.2" (cdr (assoc "version" (curl-version-info))))
    (test* "curl-easy-escape" "This%20is%20a%20test."
	   (curl-easy-escape hnd "This is a test." 0))
    (test* "curl-easy-escape" "This%20is%20a%20test%2E"
	   (curl-easy-escape hnd "This is a test." 0)))
(test* "curl-easy-unescape" "This is a test."
       (curl-easy-unescape hnd "This%20is%20a%20test%2E" 0 0))
(curl-easy-cleanup hnd)


(test-section "bare function")

(define hnd (curl-easy-init))
(test* "curl-easy-setopt (set URL)" 0
       (curl-easy-setopt hnd CURLOPT_URL "http://www.google.com/"))

;;  common
(test* "set output port" #t
       (output-port? (curl-open-port hnd CURLOPT_WRITEDATA (current-output-port))))
(test* "curl-easy-setopt (set verbose)" 0
        (curl-easy-setopt hnd CURLOPT_VERBOSE 0))
(test* "curl-easy-setopt (set body include no header)" 0
       (curl-easy-setopt hnd CURLOPT_HEADER 1))
(test* "curl-easy-perform" 0
       (curl-easy-perform hnd))

;; response
(test* "curl-easy-getinfo (response code)" 302
       (curl-easy-getinfo hnd CURLINFO_RESPONSE_CODE))
(test* "curl-easy-getinfo (effective url)" "http://www.google.com/"
       (curl-easy-getinfo hnd CURLINFO_EFFECTIVE_URL))
(test* "curl-easy-getinfo (content type)" "text/html; charset=UTF-8"
       (curl-easy-getinfo hnd CURLINFO_CONTENT_TYPE))
(curl-easy-cleanup hnd)



(test-section "cooked function")
;; make <curl> object
(define curl (make <curl> :url "http://www.google.com/" 
		   :options '("-L" "--compressed" "--header=X-hoge0: hoge,X-hoge1: hoge,X-hoge2: hoge")))
(test* "<curl>" #t
       (is-a? curl <curl>))
(define op (curl-open-output-port curl))
(test* "curl-output-port" #t
       (output-port? op))
(define hp (curl-open-header-port curl))
(test* "curl-header-port" #t
       (output-port? hp))
(test* "curl-perform" #t
       (curl))
(test* "output" #t 
       (is-a?
	(#/Google/ (string-incomplete->complete (get-output-string op) :omit))
	<regmatch>))
(test* "header" "gws"
        (cadr  (assoc "server" (curl-headers->alist (get-output-string hp) -1))))
(test* "info" 200
       (cdr (assq 'RESPONSE_CODE (curl-getinfo curl))))

(test-section "http-get")
;; wrapper
(receive (res header body)
    (http-get "www.google.com" "/")
  (begin
    (test* "http-get response code" "200" res)
    (test* "http-get header" "gws" (cadr  (assoc "server" header)))
    (test* "http-get body" #t 
	   (is-a? (#/Google/ (string-incomplete->complete body :omit)) <regmatch>))))

(test-section "progress bar")
(let* ((c (make <curl> :url "http://www.google.com/" :options "-L"))
       (op (curl-open-output-port c)))
  (curl-set-progress! c #t)
  (c))

(test-section "multi interface")
(let* ((c (make <curl> :url "http://www.google.co.jp/" :options "-L"))
       (c2 (make <curl> :url "http://www.yahoo.co.jp/" :options "-L"))
       (op (curl-open-output-port c))
       (hp (curl-open-header-port c))
       (op2 (curl-open-output-port c2))
       (hp2 (curl-open-header-port c2))
       (cm (make <curl-multi> :timeout 30 :maxconnect 25 :pipelining #t)))
  (curl-handler-add! cm c)
  (curl-handler-add! cm c2)
  (curl-async-perform cm))

(test* "curl-global-cleanup" #t
       (eq? (undefined) (curl-global-cleanup)))

;; epilogue
(test-end)

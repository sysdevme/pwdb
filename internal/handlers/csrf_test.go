package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRFMiddlewareProtectsBrowserForms(t *testing.T) {
	server := &Server{}
	handler := server.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	cookies := getRecorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != csrfCookieName {
		t.Fatalf("expected CSRF cookie, got %#v", cookies)
	}

	missingRecorder := httptest.NewRecorder()
	missingRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"email": {"user@example.com"}}.Encode()))
	missingRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingRequest.AddCookie(cookies[0])
	handler.ServeHTTP(missingRecorder, missingRequest)
	if missingRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected missing token to be rejected, got %d", missingRecorder.Code)
	}

	validRecorder := httptest.NewRecorder()
	validRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{csrfFormField: {cookies[0].Value}}.Encode()))
	validRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validRequest.AddCookie(cookies[0])
	handler.ServeHTTP(validRecorder, validRequest)
	if validRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected valid token to pass, got %d", validRecorder.Code)
	}
}

func TestCSRFMiddlewareDoesNotInterceptJSONAPI(t *testing.T) {
	server := &Server{}
	handler := server.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/desktop/login", strings.NewReader(`{"email":"user@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected JSON API request to pass, got %d", recorder.Code)
	}
}

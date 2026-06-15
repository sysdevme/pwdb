package handlers

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

const (
	csrfTokenCtxKey ctxKey = 2
	csrfCookieName         = "pm_csrf"
	csrfFormField          = "csrf_token"
)

func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := csrfTokenFromCookie(r)
		if token == "" {
			var err error
			token, err = randomToken()
			if err != nil {
				http.Error(w, "failed to initialize request protection", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				Secure:   isSecureRequest(r),
				SameSite: http.SameSiteLaxMode,
			})
		}

		r = r.WithContext(context.WithValue(r.Context(), csrfTokenCtxKey, token))
		if isBrowserFormPost(r) && !validCSRFToken(r, token) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func csrfTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func csrfTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(csrfTokenCtxKey).(string)
	return token
}

func isBrowserFormPost(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	return strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(contentType, "multipart/form-data")
}

func validCSRFToken(r *http.Request, expected string) bool {
	provided := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if provided == "" {
		contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
		var err error
		if strings.HasPrefix(contentType, "multipart/form-data") {
			err = r.ParseMultipartForm(32 << 20)
		} else {
			err = r.ParseForm()
		}
		if err != nil {
			return false
		}
		provided = strings.TrimSpace(r.FormValue(csrfFormField))
	}
	if expected == "" || len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

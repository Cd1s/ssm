package cloud

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parseTokenResponse must not accept any 2xx body. A server (or proxy/captive portal) that
// answers 200 with `{}` or `{"token":""}` must not make Login/Register return ("", nil), which
// would let the CLI save cloud.json with an empty token and print "Logged in.".
func TestLoginRejectsAnEmptyToken(t *testing.T) {
	for name, body := range map[string]string{"empty object": `{}`, "empty token": `{"token":""}`, "blank token": `{"token":"  \t"}`, "html": `<html>`} { //nolint:gosec // test response bodies, not credentials
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			token, err := Login(server.URL, "a@b.c", "pw")
			t.Logf("Login -> token=%q err=%v", token, err)
			if err == nil && strings.TrimSpace(token) == "" {
				t.Errorf("Login returned an empty token without an error")
			}
			token, err = Register(server.URL, "a@b.c", "pw")
			if err == nil && strings.TrimSpace(token) == "" {
				t.Errorf("Register returned an empty token without an error")
			}
		})
	}
}

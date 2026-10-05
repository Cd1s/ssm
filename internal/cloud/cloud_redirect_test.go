package cloud

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestAuthRedirectRefusesDifferentHost(t *testing.T) {
	for name, authenticate := range map[string]func(string, string, string) (string, error){
		"login": Login, "register": Register,
	} {
		for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			t.Run(name+"/"+strconv.Itoa(status), func(t *testing.T) {
				var requests atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					_, _ = io.WriteString(writer, `{"token":"redirect-token"}`)
				}))
				t.Cleanup(target.Close)
				source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					http.Redirect(writer, request, target.URL+"/token", status)
				}))
				t.Cleanup(source.Close)

				token, err := authenticate(source.URL, "redirect@example.test", "test-password")
				if err == nil || err.Error() != "refusing to follow a redirect to a different host or to plain http" {
					t.Errorf("authenticate error = %v, want fixed redirect refusal", err)
				}
				if token != "" {
					t.Errorf("authenticate returned token %q", token)
				}
				if count := requests.Load(); count != 0 {
					t.Errorf("redirect target received %d requests, want 0", count)
				}
			})
		}
	}
}

func TestAuthRedirectFollowsSameHost(t *testing.T) {
	for name, authenticate := range map[string]func(string, string, string) (string, error){
		"login": Login, "register": Register,
	} {
		for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			t.Run(name+"/"+strconv.Itoa(status), func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					if request.URL.Path != "/token" {
						http.Redirect(writer, request, "/token", status)
						return
					}
					requests.Add(1)
					if request.Method != http.MethodPost {
						t.Errorf("redirect method = %q, want POST", request.Method)
					}
					var body struct {
						Email    string `json:"email"`
						Password string `json:"password"`
					}
					if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
						t.Errorf("decode redirected body: %v", err)
					}
					if body.Email != "redirect@example.test" || body.Password != "test-password" {
						t.Error("same-host redirect did not preserve the authentication body")
					}
					_, _ = io.WriteString(writer, `{"token":"redirect-token"}`)
				}))
				t.Cleanup(server.Close)

				token, err := authenticate(server.URL, "redirect@example.test", "test-password")
				if err != nil || token != "redirect-token" {
					t.Errorf("authenticate = (%q, %v), want redirect-token and no error", token, err)
				}
				if count := requests.Load(); count != 1 {
					t.Errorf("same-host target received %d requests, want 1", count)
				}
			})
		}
	}
}

func TestAuthRedirectRefusesHTTPSDowngrade(t *testing.T) {
	var requests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(writer, `{"token":"redirect-token"}`)
	}))
	t.Cleanup(plain.Close)
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, plain.URL+"/token", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(tlsServer.Close)

	pool := x509.NewCertPool()
	pool.AddCert(tlsServer.Certificate())
	oldClient := httpClient
	httpClient = &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: checkRedirect,
	}
	t.Cleanup(func() { httpClient = oldClient })

	if _, err := Login(tlsServer.URL, "redirect@example.test", "test-password"); err == nil || err.Error() != "refusing to follow a redirect to a different host or to plain http" {
		t.Fatalf("Login error = %v, want HTTPS downgrade refusal", err)
	}
	if count := requests.Load(); count != 0 {
		t.Fatalf("plain redirect target received %d requests, want 0", count)
	}
}

func TestAuthRedirectRetainsTenRedirectLimit(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Redirect(writer, request, "/auth/login", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)

	_, err := Login(server.URL, "redirect@example.test", "test-password")
	if err == nil || err.Error() != "stopped after 10 redirects" {
		t.Errorf("Login error = %v, want ten-redirect limit", err)
	}
	if count := requests.Load(); count != 10 {
		t.Errorf("redirect loop received %d requests, want 10", count)
	}
}

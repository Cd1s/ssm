package cloud

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type countingReader struct {
	reader io.Reader
	count  int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += n
	return n, err
}

func TestParseErrorBoundsResponseBody(t *testing.T) {
	body := `{"error":"` + strings.Repeat("x", 2<<20) + `"}`
	reader := &countingReader{reader: strings.NewReader(body)}
	err := parseError(&http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(reader)})
	if err == nil || err.Error() != "response body is too large" {
		t.Fatalf("parseError = %v, want response body is too large", err)
	}
	if reader.count > int(maxResponseBodyBytes)+1 {
		t.Fatalf("parseError read %d bytes, want at most %d", reader.count, maxResponseBodyBytes+1)
	}
}

func TestParseTokenResponseBoundsResponseBody(t *testing.T) {
	body := `{"token":"` + strings.Repeat("x", 2<<20) + `"}`
	reader := &countingReader{reader: strings.NewReader(body)}
	_, err := parseTokenResponse(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(reader)})
	if err == nil || err.Error() != "response body is too large" {
		t.Fatalf("parseTokenResponse = %v, want response body is too large", err)
	}
	if reader.count > int(maxResponseBodyBytes)+1 {
		t.Fatalf("parseTokenResponse read %d bytes, want at most %d", reader.count, maxResponseBodyBytes+1)
	}
}

func TestCheckVerifiedBoundsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"verified":true,"padding":"`+strings.Repeat("x", 2<<20)+`"}`)
	}))
	t.Cleanup(server.Close)
	if CheckVerified(&CloudConfig{Server: server.URL, Token: "token"}) {
		t.Fatal("CheckVerified succeeded with an oversized response")
	}
}

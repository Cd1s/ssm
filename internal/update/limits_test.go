package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/provenance"
	"ssm/internal/releaseasset"
)

func TestOversizedReleaseMetadataStopsBeforeAssetsAndPreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := migrationTestExecutable(t, []byte("metadata preserved executable"))
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = io.WriteString(w, strings.Repeat(" ", maxMetadata+1))
	}))
	defer server.Close()
	apiBaseURL = server.URL
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if _, err := Download("v1.4.4"); err == nil {
		t.Fatal("oversized release metadata authorized an update")
	}
	if len(paths) != 1 || paths[0] != "/repos/owner/repo/releases" {
		t.Fatalf("oversized metadata requests = %q, want metadata only", paths)
	}
	assertMigrationFile(t, exe, []byte("metadata preserved executable"))
}

func TestDuplicateAndOversizedChecksumsFailClosed(t *testing.T) {
	line := strings.Repeat("a", sha256.Size*2) + "  " + assetName() + "\n"
	if _, err := checksumForAsset([]byte(line+line), assetName()); err == nil {
		t.Fatal("duplicate checksum records were accepted")
	}

	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := migrationTestExecutable(t, []byte("checksum preserved executable"))
	binaryRequested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v1.4.5/checksums.txt":
			_, _ = io.WriteString(w, line+strings.Repeat(" ", maxChecksums+1))
		default:
			binaryRequested = true
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if err := DownloadVersion("v1.4.5", false); err == nil {
		t.Fatal("oversized checksum manifest authorized an update")
	}
	if binaryRequested {
		t.Fatal("oversized checksum manifest led to another asset request")
	}
	assertMigrationFile(t, exe, []byte("checksum preserved executable"))
}

func TestEmptyMalformedAndOversizedProvenanceFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		bundle []byte
	}{
		{name: "empty", bundle: nil},
		{name: "malformed", bundle: []byte("{")},
		{name: "oversized", bundle: bytes.Repeat([]byte(" "), provenance.MaxBundleBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")
			exe := migrationTestExecutable(t, []byte("provenance preserved executable"))
			const version = "v1.4.5"
			payload := []byte("untrusted replacement")
			digest := sha256.Sum256(payload)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/owner/repo/releases/download/" + version + "/checksums.txt":
					_, _ = fmt.Fprintf(w, "%x  %s\n", digest, assetName())
				case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
					_, _ = w.Write(test.bundle)
				case "/owner/repo/releases/download/" + version + "/" + assetName():
					_, _ = w.Write(payload)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			downloadBaseURL = server.URL
			httpClient = server.Client()

			if err := DownloadVersion(version, false); err == nil {
				t.Fatalf("%s provenance authorized an update", test.name)
			}
			assertMigrationFile(t, exe, []byte("provenance preserved executable"))
		})
	}
}

func TestDeclaredAndChunkedOversizedBinariesFailClosed(t *testing.T) {
	for _, test := range []struct {
		name          string
		contentLength int64
		body          func(*int64) io.ReadCloser
		wantRead      int64
	}{
		{
			name:          "declared",
			contentLength: maxBinary + 1,
			body: func(read *int64) io.ReadCloser {
				return io.NopCloser(countingByteReader(maxBinary+1, read))
			},
			wantRead: 0,
		},
		{
			name:          "chunked",
			contentLength: -1,
			body: func(read *int64) io.ReadCloser {
				return io.NopCloser(countingByteReader(maxBinary+8192, read))
			},
			wantRead: maxBinary + 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")
			directory := t.TempDir()
			exe := filepath.Join(directory, "ssm")
			original := []byte("binary preserved executable")
			if err := os.WriteFile(exe, original, 0751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
				t.Fatal(err)
			}
			if err := os.Chmod(exe, 0751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
				t.Fatal(err)
			}
			executablePath = func() (string, error) { return exe, nil }
			evalSymlinks = func(path string) (string, error) { return path, nil }
			verifyProvenance = func(context.Context, []byte, provenance.Request) error {
				t.Fatal("provenance verification ran after an oversized binary")
				return nil
			}

			var read int64
			httpClient = &http.Client{Transport: bridgeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				response := &http.Response{StatusCode: http.StatusOK, Status: "200 OK", ContentLength: -1}
				switch request.URL.Path {
				case "/owner/repo/releases/download/v1.4.5/checksums.txt":
					response.Body = io.NopCloser(strings.NewReader(strings.Repeat("0", sha256.Size*2) + "  " + assetName() + "\n"))
				case "/owner/repo/releases/download/v1.4.5/" + releaseasset.ProvenanceName(assetName()):
					response.Body = io.NopCloser(strings.NewReader("{}"))
				case "/owner/repo/releases/download/v1.4.5/" + assetName():
					response.ContentLength = test.contentLength
					response.Body = test.body(&read)
				default:
					response.StatusCode = http.StatusNotFound
					response.Status = "404 Not Found"
					response.Body = io.NopCloser(strings.NewReader(""))
				}
				return response, nil
			})}
			downloadBaseURL = "https://releases.example"

			err := DownloadVersion("v1.4.5", false)
			if err == nil || !strings.Contains(err.Error(), "exceeds 67108864-byte limit") {
				t.Fatalf("oversized binary error = %v", err)
			}
			if read != test.wantRead {
				t.Fatalf("binary bytes read = %d, want %d", read, test.wantRead)
			}
			assertMigrationFile(t, exe, original)
			staged, err := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
			if err != nil {
				t.Fatal(err)
			}
			if len(staged) != 0 {
				t.Fatalf("oversized binary left staged files: %q", staged)
			}
		})
	}
}

type bridgeRoundTripFunc func(*http.Request) (*http.Response, error)

func (function bridgeRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func countingByteReader(size int64, read *int64) io.Reader {
	return io.LimitReader(countingReader{read: read}, size)
}

type countingReader struct {
	read *int64
}

func (reader countingReader) Read(data []byte) (int, error) {
	for index := range data {
		data[index] = 'x'
	}
	*reader.read += int64(len(data))
	return len(data), nil
}

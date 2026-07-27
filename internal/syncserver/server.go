package syncserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"ssm/internal/privatepath"
)

const maxBlobBytes = 64 << 20

type Server struct {
	dataDir string
	users   *userStore
	mux     *http.ServeMux
}

type user struct {
	Email        string   `json:"email"`
	PasswordHash string   `json:"password_hash"`
	TokenHash    string   `json:"token_hash,omitempty"`
	TokenHashes  []string `json:"token_hashes,omitempty"`
	Verified     bool     `json:"verified"`
	UpdatedAt    string   `json:"updated_at"`
}

type userStore struct {
	path  string
	mu    sync.Mutex
	Users map[string]user `json:"users"`
}

func New(dataDir string) (*Server, error) {
	if dataDir == "" {
		return nil, errors.New("data dir required")
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "vaults"), 0700); err != nil {
		return nil, err
	}
	if err := chmodPrivateDir(dataDir); err != nil {
		return nil, err
	}
	if err := chmodPrivateDir(filepath.Join(dataDir, "vaults")); err != nil {
		return nil, err
	}

	store, err := loadUsers(filepath.Join(dataDir, "users.json"))
	if err != nil {
		return nil, err
	}

	s := &Server{
		dataDir: dataDir,
		users:   store,
		mux:     http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.method(http.MethodGet, s.handleHealth))
	s.mux.HandleFunc("/auth/register", s.method(http.MethodPost, s.handleRegister))
	s.mux.HandleFunc("/auth/login", s.method(http.MethodPost, s.handleLogin))
	s.mux.HandleFunc("/auth/status", s.method(http.MethodGet, s.handleStatus))
	s.mux.HandleFunc("/sync", s.handleSync)
}

func (s *Server) method(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAuthRequest(w, r)
	if !ok {
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	token, tokenHash, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	u := user{
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		TokenHash:    tokenHash,
		TokenHashes:  []string{tokenHash},
		Verified:     true,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.users.add(u); err != nil {
		if errors.Is(err, errUserExists) {
			writeError(w, http.StatusConflict, "account already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not save account")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAuthRequest(w, r)
	if !ok {
		return
	}

	u, found := s.users.get(req.Email)
	if !found || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, tokenHash, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	u.TokenHash = tokenHash
	u.TokenHashes = appendTokenHash(u.TokenHashes, tokenHash)
	u.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.users.update(u); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save account")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"verified": u.Verified})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		s.handlePush(w, r)
	case http.MethodGet:
		s.handlePull(w, r)
	case http.MethodHead:
		s.handleHead(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	defer r.Body.Close()

	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBlobBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "sync blob too large")
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "sync blob required")
		return
	}

	path := s.vaultPath(u.Email)
	if err := writePrivateFile(path, data); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store sync blob")
		return
	}
	w.Header().Set("ETag", quoteETag(hashBytes(data)))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	data, err := os.ReadFile(s.vaultPath(u.Email))
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "no vault found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not read sync blob")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", quoteETag(hashBytes(data)))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleHead(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	data, err := os.ReadFile(s.vaultPath(u.Email))
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "no vault found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not read sync blob")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("ETag", quoteETag(hashBytes(data)))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (user, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return user{}, false
	}
	tokenHash := hashToken(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
	u, ok := s.users.getByToken(tokenHash)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return user{}, false
	}
	return u, true
}

func (s *Server) vaultPath(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	return filepath.Join(s.dataDir, "vaults", hex.EncodeToString(sum[:])+".blob")
}

type authRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func decodeAuthRequest(w http.ResponseWriter, r *http.Request) (authRequest, bool) {
	defer r.Body.Close()
	var req authRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return authRequest{}, false
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "valid email required")
		return authRequest{}, false
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return authRequest{}, false
	}
	return req, true
}

var errUserExists = errors.New("user exists")

func loadUsers(path string) (*userStore, error) {
	store := &userStore{path: path, Users: map[string]user{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := store.saveLocked(); err != nil {
				return nil, err
			}
			return store, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}
	if store.Users == nil {
		store.Users = map[string]user{}
	}
	return store, nil
}

func (s *userStore) add(u user) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(u.Email)
	if _, exists := s.Users[key]; exists {
		return errUserExists
	}
	s.Users[key] = u
	return s.saveLocked()
}

func (s *userStore) update(u user) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Users[strings.ToLower(u.Email)] = u
	return s.saveLocked()
}

func (s *userStore) get(email string) (user, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.Users[strings.ToLower(email)]
	return u, ok
}

func (s *userStore) getByToken(tokenHash string) (user, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if constantTimeEqual(u.TokenHash, tokenHash) {
			return u, true
		}
		for _, candidate := range u.TokenHashes {
			if constantTimeEqual(candidate, tokenHash) {
				return u, true
			}
		}
	}
	return user{}, false
}

func constantTimeEqual(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *userStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(s.path, data)
}

func newToken() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(buf)
	return token, hashToken(token), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func quoteETag(value string) string {
	return `"` + value + `"`
}

func appendTokenHash(tokens []string, tokenHash string) []string {
	if tokenHash == "" {
		return tokens
	}
	for _, existing := range tokens {
		if existing == tokenHash {
			return tokens
		}
	}
	tokens = append(tokens, tokenHash)
	if len(tokens) > 16 {
		tokens = tokens[len(tokens)-16:]
	}
	return tokens
}

func chmodPrivateDir(path string) error {
	return privatepath.RestrictDirectory(path)
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := privatepath.RestrictDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := privatepath.RestrictFile(tmpPath); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

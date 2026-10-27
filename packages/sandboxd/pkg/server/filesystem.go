// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	"sigs.k8s.io/agent-sandbox/packages/sandboxd/pkg/pathutil"
)

// Wire types live in filesystem_types.go; the /v1/metadata handler lives in
// metadata.go.

var modePattern = regexp.MustCompile(`^0[0-7]{3}$`)

// RESTServer implements the sandboxd Filesystem & Runtime REST API on top of
// net/http. All file paths are confined to rootDir: pathutil.SanitizePath
// checks each request path, and every filesystem call then goes through an
// os.Root so a symlink swapped in after the check cannot lead outside it.
type RESTServer struct {
	rootDir           string
	resolvedRoot      string
	metadataEnvPrefix string
	startTime         time.Time
	ready             atomic.Bool
	log               logr.Logger

	// environ is swappable for tests; defaults to os.Environ.
	environ func() []string
	// metadataEnv returns the filtered /v1/metadata env map, computed once
	// on first use: the daemon's environment is immutable after start.
	metadataEnv func() map[string]string
	// afterResolve runs between the path check and the filesystem call; tests
	// use it to swap in a symlink at that moment.
	afterResolve func()
}

// NewRESTServer builds a RESTServer rooted at rootDir. rootDir must be
// non-empty. Only environment variables carrying metadataEnvPrefix are exposed
// on /v1/metadata. The server starts ready; SetReady(false) flips /v1/health
// to 503.
func NewRESTServer(rootDir, metadataEnvPrefix string, log logr.Logger) *RESTServer {
	if metadataEnvPrefix == "" {
		metadataEnvPrefix = "SANDBOX_"
	}
	resolvedRoot, err := pathutil.SanitizePath(rootDir, ".")
	if err != nil {
		resolvedRoot, _ = filepath.Abs(filepath.Clean(rootDir))
	}
	s := &RESTServer{
		rootDir:           rootDir,
		resolvedRoot:      resolvedRoot,
		metadataEnvPrefix: metadataEnvPrefix,
		startTime:         time.Now(),
		log:               log,
		environ:           os.Environ,
	}
	s.ready.Store(true)
	s.metadataEnv = sync.OnceValue(s.buildMetadataEnv)
	return s
}

// SetReady toggles the /v1/health response between 200 and 503. Flipped to
// false at the start of graceful shutdown so Kubernetes stops routing.
func (s *RESTServer) SetReady(ready bool) {
	s.ready.Store(ready)
}

// Handler returns the fully routed http.Handler for the REST API.
func (s *RESTServer) Handler() http.Handler {
	mux := http.NewServeMux()
	// A "GET" pattern also serves HEAD with the body suppressed, giving the
	// KEP's existence probe (HEAD /v1/files/{path}) for free.
	mux.HandleFunc("GET /v1/files/{path...}", s.handleGetFile)
	mux.HandleFunc("PUT /v1/files/{path...}", s.handlePutFile)
	mux.HandleFunc("DELETE /v1/files/{path...}", s.handleDeleteFile)
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("GET /v1/metadata", s.handleMetadata)
	return mux
}

func (s *RESTServer) writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.log.V(4).Info("failed to encode response body", "error", err)
	}
}

func (s *RESTServer) writeError(w http.ResponseWriter, httpCode int, code, message string) {
	s.writeJSON(w, httpCode, APIError{Code: code, Message: message})
}

// sandboxPath is a request path checked against the sandbox root.
type sandboxPath struct {
	// root is the sandbox root; filesystem calls use it with rel so the
	// kernel-level confinement of os.Root holds even if the path changes
	// after the check.
	root *os.Root
	// rel is the path relative to the resolved root ("." for the root).
	rel string
	// abs is the checked absolute path, for comparisons only.
	abs string
}

// resolvePath sanitizes the {path...} wildcard against the sandbox root,
// writing the spec-mandated error response on failure. The caller closes
// p.root.
func (s *RESTServer) resolvePath(w http.ResponseWriter, r *http.Request) (sandboxPath, bool) {
	target, err := pathutil.SanitizePath(s.rootDir, r.PathValue("path"))
	if err != nil {
		if errors.Is(err, pathutil.ErrPathEscapes) {
			s.writeEscape(w)
		} else {
			s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		}
		return sandboxPath{}, false
	}
	rel, err := filepath.Rel(s.resolvedRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// The root itself was re-pointed since startup.
		s.writeEscape(w)
		return sandboxPath{}, false
	}
	root, err := os.OpenRoot(s.resolvedRoot)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return sandboxPath{}, false
	}
	if s.afterResolve != nil {
		s.afterResolve()
	}
	return sandboxPath{root: root, rel: rel, abs: target}, true
}

func (s *RESTServer) writeEscape(w http.ResponseWriter) {
	s.writeError(w, http.StatusForbidden, "PERMISSION_DENIED",
		"path traversal outside sandbox root is forbidden")
}

// escapedSinceCheck reports whether the request path now leads outside the
// root. os.Root fails such a call with an unexported error, so a failed
// filesystem call re-checks the path to report it as the traversal it is.
func (s *RESTServer) escapedSinceCheck(w http.ResponseWriter, r *http.Request) bool {
	if _, err := pathutil.SanitizePath(s.rootDir, r.PathValue("path")); errors.Is(err, pathutil.ErrPathEscapes) {
		s.writeEscape(w)
		return true
	}
	return false
}

func (s *RESTServer) handleGetFile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.resolvePath(w, r)
	if !ok {
		return
	}
	defer func() { _ = p.root.Close() }()

	info, err := p.root.Stat(p.rel)
	if err != nil {
		if s.escapedSinceCheck(w, r) {
			return
		}
		if os.IsNotExist(err) {
			s.writeError(w, http.StatusNotFound, "NOT_FOUND", "path does not exist within the sandbox")
		} else if os.IsPermission(err) {
			s.writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "permission denied")
		} else {
			s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		}
		return
	}

	if info.IsDir() {
		s.serveDirectoryListing(w, r, p)
		return
	}

	f, err := p.root.Open(p.rel)
	if err != nil {
		if s.escapedSinceCheck(w, r) {
			return
		}
		if os.IsPermission(err) {
			s.writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "permission denied")
		} else {
			s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		}
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	// ServeContent streams via seek + chunked io.Copy — the file is never
	// fully buffered in memory, so downloads are not size-capped. It also
	// handles HEAD, Content-Length, and Range requests, and keeps the
	// Content-Type set above.
	http.ServeContent(w, r, "", info.ModTime(), f)
}

func (s *RESTServer) serveDirectoryListing(w http.ResponseWriter, r *http.Request, p sandboxPath) {
	dirEntries, err := fs.ReadDir(p.root.FS(), filepath.ToSlash(p.rel)) // sorted by name
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	entries := make([]FileEntry, 0, len(dirEntries))
	for _, entry := range dirEntries {
		info, err := entry.Info()
		if err != nil {
			continue // entry vanished between ReadDir and Info
		}
		if entry.Type()&os.ModeSymlink != 0 {
			// Resolve the link's type through the root: os.Root refuses links
			// escaping the sandbox root, so they are omitted from the listing.
			// Broken links are also omitted.
			info, err = p.root.Stat(filepath.Join(p.rel, entry.Name()))
			if err != nil {
				continue
			}
		}
		entryType := "file"
		if info.IsDir() {
			entryType = "directory"
		}
		entries = append(entries, FileEntry{
			Name:       entry.Name(),
			Size:       info.Size(),
			Type:       entryType,
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
			Mode:       fmt.Sprintf("%04o", info.Mode().Perm()),
		})
	}

	relPath := r.PathValue("path")
	if !strings.HasPrefix(relPath, "/") {
		relPath = "/" + relPath
	}
	s.writeJSON(w, http.StatusOK, DirectoryListing{Path: relPath, Entries: entries})
}

func (s *RESTServer) handlePutFile(w http.ResponseWriter, r *http.Request) {
	mode := os.FileMode(0o644)
	if modeParam := r.URL.Query().Get("mode"); modeParam != "" {
		if !modePattern.MatchString(modeParam) {
			s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT",
				fmt.Sprintf("mode %q must match ^0[0-7]{3}$", modeParam))
			return
		}
		parsed, err := strconv.ParseUint(modeParam, 8, 32)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		mode = os.FileMode(parsed)
	}

	p, ok := s.resolvePath(w, r)
	if !ok {
		return
	}
	defer func() { _ = p.root.Close() }()
	if info, err := p.root.Stat(p.rel); err == nil && info.IsDir() {
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "target path is a directory")
		return
	}

	body, cleanup, err := requestFileBody(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	defer cleanup()

	if err := atomicWrite(p.root, p.rel, body, mode); err != nil {
		if s.escapedSinceCheck(w, r) {
			return
		}
		if os.IsPermission(err) {
			s.writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "permission denied")
		} else {
			s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// requestFileBody returns the file payload reader for a PUT request: the raw
// body, or the required "file" part of a multipart/form-data upload.
func requestFileBody(r *http.Request) (io.Reader, func(), error) {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if contentType != "" && err == nil && mediaType == "multipart/form-data" {
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, nil, fmt.Errorf("invalid multipart body: %w", err)
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return nil, nil, fmt.Errorf("multipart body is missing the required %q part", "file")
			}
			if err != nil {
				return nil, nil, fmt.Errorf("invalid multipart body: %w", err)
			}
			if part.FormName() == "file" {
				return part, func() { _ = part.Close() }, nil
			}
			_ = part.Close()
		}
	}
	return r.Body, func() {}, nil
}

// atomicWrite streams src into target using the temp-file-then-rename
// strategy. Parent directories are created automatically.
//
// Concurrency: handlers run in parallel (one goroutine per request, no
// cross-request locking). Each successful rename(2) publishes a complete file
// atomically, so an already-open reader sees either the previous complete file
// or the new one. A concurrent delete can remove the temporary file or its
// parent directory before rename, in which case the write fails.
func atomicWrite(root *os.Root, name string, src io.Reader, mode os.FileMode) (err error) {
	dir := filepath.Dir(name)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	tmpName, tmpFile, err := createTemp(root, dir)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	// Remove the temp file on any failure, including client disconnects
	// mid-upload.
	defer func() {
		if err != nil {
			_ = tmpFile.Close()
			_ = root.Remove(tmpName)
		}
	}()

	if err = tmpFile.Chmod(mode); err != nil {
		return fmt.Errorf("failed to set file mode: %w", err)
	}
	if _, err = io.Copy(tmpFile, src); err != nil {
		return fmt.Errorf("failed to write file contents: %w", err)
	}
	if err = tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}
	if err = root.Rename(tmpName, name); err != nil {
		return fmt.Errorf("failed to move file into place: %w", err)
	}
	return nil
}

// createTemp creates a new, exclusively opened temporary file in dir under
// root, like os.CreateTemp (which has no os.Root equivalent).
func createTemp(root *os.Root, dir string) (string, *os.File, error) {
	for range 16 {
		name := filepath.Join(dir, ".sandboxd-tmp-"+rand.Text())
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return name, f, err
	}
	return "", nil, errors.New("could not find an unused temporary file name")
}

func (s *RESTServer) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.resolvePath(w, r)
	if !ok {
		return
	}
	defer func() { _ = p.root.Close() }()

	if _, err := p.root.Lstat(p.rel); err != nil {
		if s.escapedSinceCheck(w, r) {
			return
		}
		if os.IsNotExist(err) {
			s.writeError(w, http.StatusNotFound, "NOT_FOUND", "path does not exist within the sandbox")
		} else {
			s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		}
		return
	}

	recursive := false
	if recParam := r.URL.Query().Get("recursive"); recParam != "" {
		parsed, err := strconv.ParseBool(recParam)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT",
				fmt.Sprintf("recursive %q must be a boolean", recParam))
			return
		}
		recursive = parsed
	}

	// With --root-dir=/ the root is the whole filesystem; clearing it would
	// remove the daemon, the runtime and every mount.
	if p.abs == string(filepath.Separator) {
		s.writeError(w, http.StatusForbidden, "PERMISSION_DENIED",
			"refusing to delete the filesystem root")
		return
	}

	if p.rel == "." {
		if !recursive {
			s.writeError(w, http.StatusConflict, "CONFLICT",
				"cannot delete the sandbox root; pass recursive=true to clear its contents")
			return
		}
		// For the sandbox root directory itself, clear its contents rather
		// than deleting the volume mount entity.
		dirEntries, err := fs.ReadDir(p.root.FS(), ".")
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		for _, entry := range dirEntries {
			if err := p.root.RemoveAll(entry.Name()); err != nil {
				s.writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var removeErr error
	if recursive {
		removeErr = p.root.RemoveAll(p.rel)
	} else {
		removeErr = p.root.Remove(p.rel)
	}
	if removeErr != nil {
		if s.escapedSinceCheck(w, r) {
			return
		}
		switch {
		case errors.Is(removeErr, syscall.ENOTEMPTY) || errors.Is(removeErr, syscall.EEXIST):
			s.writeError(w, http.StatusConflict, "CONFLICT",
				"directory is not empty; pass recursive=true to remove it")
		case os.IsPermission(removeErr):
			s.writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "permission denied")
		default:
			s.writeError(w, http.StatusInternalServerError, "INTERNAL", removeErr.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *RESTServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		s.writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "sandboxd is shutting down")
		return
	}
	s.writeJSON(w, http.StatusOK, HealthResponse{
		Status:        "ok",
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
	})
}

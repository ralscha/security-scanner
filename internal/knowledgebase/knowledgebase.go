// Package knowledgebase prepares a bounded, read-only inventory of untrusted
// text supplied alongside a repository scan.
package knowledgebase

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	DefaultMaxDocuments     = 100
	DefaultMaxDocumentBytes = int64(2 * 1024 * 1024)
	DefaultMaxTotalBytes    = int64(10 * 1024 * 1024)
)

type Options struct {
	MaxDocuments     int   `json:"max_documents,omitempty"`
	MaxDocumentBytes int64 `json:"max_document_bytes,omitempty"`
	MaxTotalBytes    int64 `json:"max_total_bytes,omitempty"`
}

type Document struct {
	ID         string `json:"id"`
	SourcePath string `json:"source_path"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Text       string `json:"-"`
	identity   os.FileInfo
	fileID     string
}

type Prepared struct {
	SourceRoots []string   `json:"source_roots"`
	Documents   []Document `json:"documents"`
	Digest      string     `json:"digest"`
	options     Options
}

type DriftError struct{ Err error }

func (e *DriftError) Error() string { return e.Err.Error() }
func (e *DriftError) Unwrap() error { return e.Err }

func DefaultOptions() Options {
	return Options{MaxDocuments: DefaultMaxDocuments, MaxDocumentBytes: DefaultMaxDocumentBytes, MaxTotalBytes: DefaultMaxTotalBytes}
}

func NormalizeOptions(options Options) (Options, error) {
	if options.MaxDocuments < 0 || options.MaxDocumentBytes < 0 || options.MaxTotalBytes < 0 {
		return Options{}, fmt.Errorf("knowledge-base limits cannot be negative")
	}
	defaults := DefaultOptions()
	if options.MaxDocuments == 0 {
		options.MaxDocuments = defaults.MaxDocuments
	}
	if options.MaxDocumentBytes == 0 {
		options.MaxDocumentBytes = defaults.MaxDocumentBytes
	}
	if options.MaxTotalBytes == 0 {
		options.MaxTotalBytes = defaults.MaxTotalBytes
	}
	return options, nil
}

func Prepare(paths []string, options Options) (*Prepared, error) {
	options, err := NormalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return &Prepared{SourceRoots: []string{}, Documents: []Document{}, Digest: emptyDigest(), options: options}, nil
	}
	roots := make([]string, 0, len(paths))
	candidates := make([]string, 0)
	seenRoots := make(map[string]struct{})
	for _, supplied := range paths {
		resolved, err := resolveRoot(supplied)
		if err != nil {
			return nil, err
		}
		key := pathKey(resolved)
		if _, exists := seenRoots[key]; exists {
			continue
		}
		seenRoots[key] = struct{}{}
		roots = append(roots, resolved)
		info, err := os.Lstat(resolved)
		if err != nil {
			return nil, fmt.Errorf("inspect knowledge-base path %s: %w", resolved, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("knowledge-base root must not be a symbolic link: %s", resolved)
		}
		switch {
		case info.Mode().IsRegular():
			if !supported(resolved) {
				return nil, fmt.Errorf("unsupported knowledge-base document: %s", resolved)
			}
			candidates = append(candidates, resolved)
		case info.IsDir():
			found := 0
			err := filepath.WalkDir(resolved, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if path == resolved {
					return nil
				}
				if entry.Type()&os.ModeSymlink != 0 {
					return fmt.Errorf("knowledge-base path must not contain symbolic links: %s", path)
				}
				if entry.IsDir() {
					return nil
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("knowledge-base path contains a non-regular file: %s", path)
				}
				if supported(path) {
					found++
					candidates = append(candidates, path)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("discover knowledge-base documents: %w", err)
			}
			after, err := os.Lstat(resolved)
			if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(info, after) {
				return nil, fmt.Errorf("knowledge-base directory changed during discovery: %s", resolved)
			}
			if found == 0 {
				return nil, fmt.Errorf("knowledge-base directory contains no supported documents: %s", resolved)
			}
		default:
			return nil, fmt.Errorf("knowledge-base root must be a regular file or directory: %s", resolved)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return pathKey(roots[i]) < pathKey(roots[j]) })
	sort.Slice(candidates, func(i, j int) bool { return pathKey(candidates[i]) < pathKey(candidates[j]) })
	documents := make([]Document, 0, len(candidates))
	seenFiles := make(map[string]struct{})
	var total int64
	for _, path := range candidates {
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("resolve knowledge-base document %s: %w", path, err)
		}
		canonical, err = filepath.Abs(canonical)
		if err != nil {
			return nil, fmt.Errorf("resolve knowledge-base document %s: %w", path, err)
		}
		key := pathKey(canonical)
		if _, exists := seenFiles[key]; exists {
			continue
		}
		seenFiles[key] = struct{}{}
		if len(documents) >= options.MaxDocuments {
			return nil, fmt.Errorf("knowledge base exceeds maximum document count %d", options.MaxDocuments)
		}
		document, err := readDocument(canonical, options.MaxDocumentBytes)
		if err != nil {
			return nil, err
		}
		total += int64(len(document.Text))
		if total > options.MaxTotalBytes {
			return nil, fmt.Errorf("knowledge base exceeds maximum normalized text size %d bytes", options.MaxTotalBytes)
		}
		documents = append(documents, document)
	}
	return &Prepared{SourceRoots: roots, Documents: documents, Digest: digestDocuments(documents), options: options}, nil
}

func Verify(prepared *Prepared) error {
	if prepared == nil {
		return fmt.Errorf("knowledge-base inventory is required")
	}
	current, err := Prepare(prepared.SourceRoots, prepared.options)
	if err != nil {
		return &DriftError{Err: fmt.Errorf("knowledge base changed after inventory: %w", err)}
	}
	if current.Digest != prepared.Digest || len(current.Documents) != len(prepared.Documents) {
		return &DriftError{Err: fmt.Errorf("knowledge base changed after inventory")}
	}
	for i := range current.Documents {
		left, right := current.Documents[i], prepared.Documents[i]
		if left.ID != right.ID || left.SHA256 != right.SHA256 || left.Size != right.Size || left.Text != right.Text ||
			!sameDocumentFile(left, right) {
			return &DriftError{Err: fmt.Errorf("knowledge base changed after inventory: %s", right.Name)}
		}
	}
	return nil
}

func VerifyDocument(document Document) error {
	current, err := readDocument(document.SourcePath, max(document.Size, 1))
	if err != nil {
		return err
	}
	if current.ID != document.ID || current.Size != document.Size || current.SHA256 != document.SHA256 || current.Text != document.Text ||
		!sameDocumentFile(current, document) {
		return &DriftError{Err: fmt.Errorf("knowledge-base document changed after inventory: %s", document.Name)}
	}
	return nil
}

func readDocument(path string, maxBytes int64) (Document, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return Document{}, fmt.Errorf("inspect knowledge-base document %s: %w", path, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return Document{}, fmt.Errorf("knowledge-base document must remain a non-symlink regular file: %s", path)
	}
	if before.Size() > maxBytes {
		return Document{}, fmt.Errorf("knowledge-base document exceeds maximum size %d bytes: %s", maxBytes, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("read knowledge-base document %s: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Document{}, fmt.Errorf("inspect opened knowledge-base document %s: %w", path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return Document{}, fmt.Errorf("knowledge-base document changed while opening: %s", path)
	}
	fileID, err := fileIdentity(file)
	if err != nil {
		return Document{}, fmt.Errorf("identify knowledge-base document %s: %w", path, err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return Document{}, fmt.Errorf("read knowledge-base document %s: %w", path, err)
	}
	after, err := file.Stat()
	if err != nil {
		return Document{}, fmt.Errorf("reinspect opened knowledge-base document %s: %w", path, err)
	}
	namedAfter, err := os.Lstat(path)
	if err != nil {
		return Document{}, fmt.Errorf("reinspect knowledge-base document %s: %w", path, err)
	}
	if namedAfter.Mode()&os.ModeSymlink != 0 || !namedAfter.Mode().IsRegular() ||
		!os.SameFile(opened, after) || !os.SameFile(after, namedAfter) || after.Size() != int64(len(data)) {
		return Document{}, fmt.Errorf("knowledge-base document changed while reading: %s", path)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return Document{}, fmt.Errorf("knowledge-base document contains a NUL byte: %s", path)
	}
	if !utf8.Valid(data) {
		return Document{}, fmt.Errorf("knowledge-base document is not valid UTF-8: %s", path)
	}
	digest := sha256.Sum256(data)
	identity := sha256.Sum256([]byte(pathKey(path)))
	return Document{
		ID: "kb-" + fmt.Sprintf("%x", identity[:8]), SourcePath: path, Name: filepath.Base(path),
		Size: int64(len(data)), SHA256: fmt.Sprintf("%x", digest[:]), Text: strings.ReplaceAll(string(data), "\r\n", "\n"),
		identity: after, fileID: fileID,
	}, nil
}

func sameDocumentFile(left, right Document) bool {
	return left.identity != nil && right.identity != nil && os.SameFile(left.identity, right.identity) && left.fileID == right.fileID
}

func resolveRoot(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("knowledge-base path cannot be empty")
	}
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	} else if strings.HasPrefix(path, "~") {
		return "", fmt.Errorf("knowledge-base path does not support other-user home expansion: %s", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve knowledge-base path %s: %w", path, err)
	}
	return filepath.Clean(abs), nil
}

func supported(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt", ".md", ".markdown":
		return true
	default:
		return false
	}
}

func pathKey(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func digestDocuments(documents []Document) string {
	hash := sha256.New()
	for _, document := range documents {
		if _, err := fmt.Fprintf(hash, "%s\x00%s\x00%d\n", document.ID, document.SHA256, document.Size); err != nil {
			panic(err) // crypto/sha256 never returns a write error
		}
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func emptyDigest() string { return digestDocuments(nil) }

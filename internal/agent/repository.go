package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/components/tool/utils"

	"security-scanner/internal/redact"
	"security-scanner/internal/scan"
)

const (
	maxReadLines    = 400
	maxSearchHits   = 200
	maxSearchLine   = 500
	defaultListSize = 200
)

type interval struct {
	start int
	end   int
}

type ReadTracker struct {
	mu        sync.RWMutex
	intervals map[string][]interval
	seen      map[string]bool
}

func NewReadTracker() *ReadTracker {
	return &ReadTracker{intervals: make(map[string][]interval), seen: make(map[string]bool)}
}

func (t *ReadTracker) Mark(path string, start, end int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen[path] = true
	if end >= start && start > 0 {
		t.intervals[path] = append(t.intervals[path], interval{start: start, end: end})
	}
}

func (t *ReadTracker) Complete(file scan.File) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.seen[file.Path] {
		return false
	}
	if file.Lines == 0 {
		return true
	}
	spans := append([]interval(nil), t.intervals[file.Path]...)
	if len(spans) == 0 {
		return false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	next := 1
	for _, span := range spans {
		if span.start > next {
			return false
		}
		if span.end >= next {
			next = span.end + 1
		}
		if next > file.Lines {
			return true
		}
	}
	return false
}

type Repository struct {
	root    string
	files   []scan.File
	byPath  map[string]scan.File
	tracker *ReadTracker
}

func NewRepository(inv *scan.Inventory, tracker *ReadTracker) *Repository {
	byPath := make(map[string]scan.File, len(inv.Files))
	for _, file := range inv.Files {
		byPath[file.Path] = file
	}
	return &Repository{root: inv.Root, files: inv.Files, byPath: byPath, tracker: tracker}
}

func newScanRepositories(inv *scan.Inventory, auditTracker *ReadTracker) (audit, architecture *Repository) {
	return NewRepository(inv, auditTracker), NewRepository(inv, NewReadTracker())
}

type listFilesArgs struct {
	Offset int `json:"offset,omitempty" jsonschema:"description=Zero-based result offset,minimum=0"`
	Limit  int `json:"limit,omitempty" jsonschema:"description=Maximum files to return,minimum=1,maximum=500"`
}

type listFilesResult struct {
	Files      []scan.File `json:"files"`
	NextOffset *int        `json:"next_offset,omitempty"`
	Total      int         `json:"total"`
}

type readFileArgs struct {
	Path      string `json:"path" jsonschema:"description=Exact repository-relative path from list_files"`
	StartLine int    `json:"start_line,omitempty" jsonschema:"description=First line to read; defaults to 1,minimum=1"`
	EndLine   int    `json:"end_line,omitempty" jsonschema:"description=Last line to read inclusive; omit it to read the next chunk; when set it must be at least start_line; at most 400 lines are returned,minimum=1"`
}

type searchCodeArgs struct {
	Pattern    string `json:"pattern" jsonschema:"description=RE2 regular expression to search for"`
	PathPrefix string `json:"path_prefix,omitempty" jsonschema:"description=Optional repository-relative directory or file prefix"`
	Limit      int    `json:"limit,omitempty" jsonschema:"description=Maximum matching lines,minimum=1,maximum=200"`
}

type searchHit struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

func (r *Repository) Tools() ([]tool.BaseTool, error) {
	listTool, err := utils.InferTool("list_files", "List every file in the fixed scan inventory, including line counts and deterministic skip reasons. Paginate until next_offset is absent.", r.listFilesForModel)
	if err != nil {
		return nil, err
	}
	readTool, err := utils.InferTool("read_file", "Read an inventoried text file with stable line numbers. Read every reviewable file from line 1 through its final line; use consecutive chunks for files over 400 lines. Omit end_line to read up to 400 lines from start_line.", r.readFileForModel)
	if err != nil {
		return nil, err
	}
	searchTool, err := utils.InferTool("search_code", "Search inventoried text files with an RE2 expression. Search is for discovery only and does not count a file as fully reviewed.", r.searchCodeForModel)
	if err != nil {
		return nil, err
	}
	searchFileTool, err := utils.InferTool("search_file", "Compatibility alias for search_code. Search inventoried text files with an RE2 expression; results do not count as full-file review.", r.searchFileForModel)
	if err != nil {
		return nil, err
	}
	return []tool.BaseTool{listTool, readTool, searchTool, searchFileTool}, nil
}

func (r *Repository) listFilesForModel(ctx context.Context, args listFilesArgs) (string, error) {
	result, err := r.listFiles(ctx, args)
	return modelToolResult("list_files", result, err)
}

func (r *Repository) readFileForModel(ctx context.Context, args readFileArgs) (string, error) {
	result, err := r.readFile(ctx, args)
	return modelToolResult("read_file", result, err)
}

func (r *Repository) searchCodeForModel(ctx context.Context, args searchCodeArgs) (string, error) {
	result, err := r.searchCode(ctx, args)
	return modelToolResult("search_code", result, err)
}

func (r *Repository) searchFileForModel(ctx context.Context, args searchCodeArgs) (string, error) {
	result, err := r.searchCode(ctx, args)
	return modelToolResult("search_file", result, err)
}

func modelToolResult(name, result string, err error) (string, error) {
	if err == nil {
		return result, nil
	}
	data, marshalErr := json.Marshal(struct {
		OK    bool   `json:"ok"`
		Tool  string `json:"tool"`
		Error string `json:"error"`
	}{OK: false, Tool: name, Error: redact.Text(err.Error())})
	if marshalErr != nil {
		return "", marshalErr
	}
	return string(data), nil
}

func (r *Repository) listFiles(_ context.Context, args listFilesArgs) (string, error) {
	offset := args.Offset
	if offset < 0 || offset > len(r.files) {
		return "", fmt.Errorf("offset %d is outside inventory", offset)
	}
	limit := args.Limit
	if limit <= 0 {
		limit = defaultListSize
	}
	if limit > 500 {
		limit = 500
	}
	end := min(offset+limit, len(r.files))
	result := listFilesResult{Files: r.files[offset:end], Total: len(r.files)}
	if end < len(r.files) {
		result.NextOffset = &end
	}
	data, err := json.Marshal(result)
	return string(data), err
}

func (r *Repository) readFile(_ context.Context, args readFileArgs) (string, error) {
	path, file, err := r.resolve(args.Path)
	if err != nil {
		return "", err
	}
	if !file.Reviewable {
		return "", fmt.Errorf("file %q is not reviewable: %s", file.Path, file.SkipReason)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", file.Path, err)
	}
	if err := scan.VerifyFileContent(file, content); err != nil {
		return "", err
	}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if text == "" {
		r.tracker.Mark(file.Path, 0, 0)
		return fmt.Sprintf("FILE %s (empty)\n", file.Path), nil
	}
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	start := args.StartLine
	if start <= 0 {
		start = 1
	}
	if start > len(lines) {
		return "", fmt.Errorf("start_line %d exceeds %d lines in %s", start, len(lines), file.Path)
	}
	end := args.EndLine
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if end < start {
		return "", fmt.Errorf("end_line must be at least start_line")
	}
	if end-start+1 > maxReadLines {
		end = start + maxReadLines - 1
	}

	var out strings.Builder
	fmt.Fprintf(&out, "FILE %s LINES %d-%d OF %d\n", file.Path, start, end, len(lines))
	for line := start; line <= end; line++ {
		fmt.Fprintf(&out, "%6d | %s\n", line, lines[line-1])
	}
	if end < len(lines) {
		fmt.Fprintf(&out, "NEXT start_line=%d\n", end+1)
	}
	r.tracker.Mark(file.Path, start, end)
	return out.String(), nil
}

func (r *Repository) searchCode(_ context.Context, args searchCodeArgs) (string, error) {
	if strings.TrimSpace(args.Pattern) == "" {
		return "", fmt.Errorf("pattern is required")
	}
	re, err := regexp.Compile(args.Pattern)
	if err != nil {
		return "", fmt.Errorf("invalid RE2 pattern: %w", err)
	}
	limit := args.Limit
	if limit <= 0 || limit > maxSearchHits {
		limit = maxSearchHits
	}
	prefix := strings.Trim(strings.ReplaceAll(filepath.ToSlash(args.PathPrefix), "\\", "/"), "/")
	hits := make([]searchHit, 0)
	for _, file := range r.files {
		if !file.Reviewable || (prefix != "" && file.Path != prefix && !strings.HasPrefix(file.Path, prefix+"/")) {
			continue
		}
		path, _, err := r.resolve(file.Path)
		if err != nil {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := scan.VerifyFileContent(file, content); err != nil {
			return "", err
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			if re.MatchString(scanner.Text()) {
				text := scanner.Text()
				if len(text) > maxSearchLine {
					text = text[:maxSearchLine] + "..."
				}
				hits = append(hits, searchHit{Path: file.Path, Line: line, Text: text})
				if len(hits) >= limit {
					break
				}
			}
		}
		if len(hits) >= limit {
			break
		}
	}
	data, err := json.Marshal(struct {
		Hits      []searchHit `json:"hits"`
		Truncated bool        `json:"truncated"`
	}{Hits: hits, Truncated: len(hits) >= limit})
	return string(data), err
}

func (r *Repository) resolve(requested string) (string, scan.File, error) {
	clean := strings.Trim(strings.ReplaceAll(filepath.ToSlash(requested), "\\", "/"), "/")
	file, ok := r.byPath[clean]
	if !ok {
		return "", scan.File{}, fmt.Errorf("path %q is not in the scan inventory", requested)
	}
	path := filepath.Join(r.root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(r.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", scan.File{}, fmt.Errorf("path %q escapes the scan root", requested)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", scan.File{}, fmt.Errorf("stat %q: %w", requested, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", scan.File{}, fmt.Errorf("path %q became a symlink after inventory", requested)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", scan.File{}, fmt.Errorf("resolve %q: %w", requested, err)
	}
	rel, err = filepath.Rel(r.root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", scan.File{}, fmt.Errorf("resolved path %q escapes the scan root", requested)
	}
	return resolved, file, nil
}

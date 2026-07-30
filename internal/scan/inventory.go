package scan

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gitignore "github.com/git-pkgs/gitignore"
)

var defaultExcludedDirs = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {},
	".scanner":     {},
	"node_modules": {}, "vendor": {},
	"dist": {}, "build": {}, "target": {},
	".idea": {}, ".vscode": {},
}

type InventoryOptions struct {
	MaxFileBytes int64
	OutputDir    string
	Excludes     []string
	Includes     []string
}

func BuildInventory(root string, opts InventoryOptions) (*Inventory, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve target symlinks: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("target is not a directory: %s", absRoot)
	}

	outputRel := ""
	if opts.OutputDir != "" {
		if absOutput, err := filepath.Abs(opts.OutputDir); err == nil {
			if rel, relErr := filepath.Rel(absRoot, absOutput); relErr == nil && rel != "." && !escapesRoot(rel) {
				outputRel = filepath.ToSlash(rel)
			}
		}
	}
	excludes := make(map[string]struct{}, len(opts.Excludes))
	for _, exclude := range opts.Excludes {
		clean := strings.Trim(filepath.ToSlash(filepath.Clean(exclude)), "/")
		if clean != "" && clean != "." {
			excludes[clean] = struct{}{}
		}
	}
	includes := normalizeIncludes(opts.Includes)
	ignoreMatcher := gitignore.New("")
	ignoreMatcher.AddFromFile(filepath.Join(absRoot, ".gitignore"), "")

	inv := &Inventory{Root: absRoot}
	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if entry.IsDir() && shouldSkipDir(rel, entry.Name(), outputRel, excludes) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			if ignoreMatcher.MatchPath(rel, true) {
				return filepath.SkipDir
			}
			ignoreMatcher.AddFromFile(filepath.Join(path, ".gitignore"), rel)
			return nil
		}
		if ignoreMatcher.MatchPath(rel, false) {
			return nil
		}
		if len(includes) > 0 && !includedPath(rel, includes) {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			inv.Files = append(inv.Files, File{Path: rel, Reviewable: false, SkipReason: "symlink"})
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		file := File{Path: rel, Size: info.Size(), Language: detectLanguage(rel), Reviewable: true}
		if opts.MaxFileBytes > 0 && info.Size() > opts.MaxFileBytes {
			file.Reviewable = false
			file.SkipReason = "file_too_large"
		} else {
			lines, binary, err := inspectFile(path)
			if err != nil {
				file.Reviewable = false
				file.SkipReason = "unreadable"
			} else if binary {
				file.Reviewable = false
				file.SkipReason = "binary"
			} else {
				file.Lines = lines
			}
		}
		inv.Files = append(inv.Files, file)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory target: %w", err)
	}
	sort.Slice(inv.Files, func(i, j int) bool { return inv.Files[i].Path < inv.Files[j].Path })
	return inv, nil
}

func normalizeIncludes(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.Trim(filepath.ToSlash(filepath.Clean(value)), "/")
		if value == "" || value == "." {
			return nil
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func includedPath(path string, includes []string) bool {
	for _, include := range includes {
		if path == include || strings.HasPrefix(path, include+"/") {
			return true
		}
	}
	return false
}

func shouldSkipDir(rel, name, outputRel string, excludes map[string]struct{}) bool {
	if _, ok := defaultExcludedDirs[name]; ok {
		return true
	}
	if outputRel != "" && (rel == outputRel || strings.HasPrefix(rel, outputRel+"/")) {
		return true
	}
	for excluded := range excludes {
		if rel == excluded || strings.HasPrefix(rel, excluded+"/") {
			return true
		}
	}
	return false
}

func inspectFile(path string) (lines int, binary bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false, err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()

	reader := bufio.NewReader(f)
	prefix, err := reader.Peek(8192)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return 0, false, err
	}
	if bytes.IndexByte(prefix, 0) >= 0 {
		return 0, true, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, false, err
	}
	content, err := io.ReadAll(f)
	if err != nil {
		return 0, false, err
	}
	if len(content) == 0 {
		return 0, false, nil
	}
	lines = bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		lines++
	}
	return lines, false, nil
}

func detectLanguage(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if language, ok := map[string]string{
		"dockerfile": "Dockerfile", "makefile": "Makefile", "gemfile": "Ruby",
		"go.mod": "Go module", "go.sum": "Go module", "package.json": "JSON",
	}[base]; ok {
		return language
	}
	return map[string]string{
		".go": "Go", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
		".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python", ".rb": "Ruby",
		".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".cs": "C#",
		".c": "C", ".h": "C/C++", ".cc": "C++", ".cpp": "C++", ".rs": "Rust",
		".php": "PHP", ".swift": "Swift", ".scala": "Scala", ".sh": "Shell",
		".ps1": "PowerShell", ".sql": "SQL", ".html": "HTML", ".htm": "HTML",
		".vue": "Vue", ".svelte": "Svelte", ".xml": "XML", ".yaml": "YAML",
		".yml": "YAML", ".json": "JSON", ".toml": "TOML", ".md": "Markdown",
	}[strings.ToLower(filepath.Ext(path))]
}

func escapesRoot(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

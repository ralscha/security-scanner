package scan

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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

var protectedExcludedDirs = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {}, ".scanner": {},
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

	snapshotOptions := opts
	snapshotOptions.Excludes = append([]string(nil), opts.Excludes...)
	snapshotOptions.Includes = append([]string(nil), opts.Includes...)
	inv := &Inventory{Root: absRoot, options: snapshotOptions, snapshotReady: true}
	forcedDirs := make(map[string]struct{})
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
		if entry.IsDir() {
			skip, forced := directoryDisposition(rel, entry.Name(), outputRel, excludes, includes)
			if skip {
				return filepath.SkipDir
			}
			if ignoreMatcher.MatchPath(rel, true) {
				if !explicitScopeTargets(rel, includes) {
					return filepath.SkipDir
				}
				forced = true
			}
			if forced {
				forcedDirs[rel] = struct{}{}
			}
			ignoreMatcher.AddFromFile(filepath.Join(path, ".gitignore"), rel)
			return nil
		}
		if _, protected := protectedExcludedDirs[entry.Name()]; protected {
			return nil
		}
		if ignoreMatcher.MatchPath(rel, false) && !exactlyIncluded(rel, includes) && !underForcedDir(rel, forcedDirs) {
			return nil
		}
		if len(includes) > 0 && !includedPath(rel, includes) {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			inv.Files = append(inv.Files, File{Path: rel, Reviewable: false, SkipReason: "symlink"})
			return nil
		}
		if entry.Type()&os.ModeType != 0 {
			inv.Files = append(inv.Files, File{Path: rel, Reviewable: false, SkipReason: "special_file"})
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			inv.Files = append(inv.Files, File{Path: rel, Size: info.Size(), Reviewable: false, SkipReason: "special_file"})
			return nil
		}
		file := File{Path: rel, Size: info.Size(), Language: detectLanguage(rel), Reviewable: true}
		if opts.MaxFileBytes > 0 && info.Size() > opts.MaxFileBytes {
			file.Reviewable = false
			file.SkipReason = "file_too_large"
			file.digest, err = digestFile(path)
			if err != nil {
				file.SkipReason = "unreadable"
			}
		} else {
			lines, binary, digest, err := inspectFile(path)
			if err != nil {
				file.Reviewable = false
				file.SkipReason = "unreadable"
			} else if binary {
				file.Reviewable = false
				file.SkipReason = "binary"
				file.digest = digest
			} else {
				file.Lines = lines
				file.digest = digest
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

func VerifyInventory(inv *Inventory) error {
	if inv == nil {
		return fmt.Errorf("inventory is required")
	}
	if !inv.snapshotReady {
		return nil
	}
	current, err := BuildInventory(inv.Root, inv.options)
	if err != nil {
		return &InventoryDriftError{Err: fmt.Errorf("scan target changed after inventory: %w", err)}
	}
	if len(current.Files) != len(inv.Files) {
		return &InventoryDriftError{Err: fmt.Errorf("scan target changed after inventory: file set changed")}
	}
	for index := range inv.Files {
		if inv.Files[index] != current.Files[index] {
			return &InventoryDriftError{Err: fmt.Errorf("scan target changed after inventory: %s", inv.Files[index].Path)}
		}
	}
	return nil
}

func VerifyFileContent(file File, content []byte) error {
	if file.digest == "" {
		return nil
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	if int64(len(content)) != file.Size || digest != file.digest {
		return &InventoryDriftError{Err: fmt.Errorf("file %q changed after inventory", file.Path)}
	}
	return nil
}

// InventoryDigest returns a deterministic attestation digest without exposing
// per-file digests in persisted manifests.
func InventoryDigest(inv *Inventory) string {
	if inv == nil {
		return ""
	}
	hash := sha256.New()
	for _, file := range inv.Files {
		if _, err := fmt.Fprintf(hash, "%s\x00%d\x00%d\x00%s\x00%t\x00%s\n", file.Path, file.Size, file.Lines, file.digest, file.Reviewable, file.SkipReason); err != nil {
			panic(err) // crypto/sha256 never returns a write error
		}
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
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

func directoryDisposition(rel, name, outputRel string, excludes map[string]struct{}, includes []string) (skip, forced bool) {
	if _, ok := protectedExcludedDirs[name]; ok {
		return true, false
	}
	if outputRel != "" && (rel == outputRel || strings.HasPrefix(rel, outputRel+"/")) {
		return true, false
	}
	for excluded := range excludes {
		if rel == excluded || strings.HasPrefix(rel, excluded+"/") {
			return true, false
		}
	}
	if _, ok := defaultExcludedDirs[name]; ok {
		if explicitScopeTargets(rel, includes) {
			return false, true
		}
		return true, false
	}
	return false, false
}

func explicitScopeTargets(dir string, includes []string) bool {
	for _, include := range includes {
		if include == dir || strings.HasPrefix(include, dir+"/") {
			return true
		}
	}
	return false
}

func exactlyIncluded(path string, includes []string) bool {
	return slices.Contains(includes, path)
}

func underForcedDir(path string, forcedDirs map[string]struct{}) bool {
	for dir := range forcedDirs {
		if strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

func inspectFile(path string) (lines int, binary bool, digest string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false, "", err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()

	reader := bufio.NewReader(f)
	prefix, err := reader.Peek(8192)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return 0, false, "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, false, "", err
	}
	content, err := io.ReadAll(f)
	if err != nil {
		return 0, false, "", err
	}
	digest = fmt.Sprintf("%x", sha256.Sum256(content))
	if bytes.IndexByte(prefix, 0) >= 0 {
		return 0, true, digest, nil
	}
	if len(content) == 0 {
		return 0, false, digest, nil
	}
	lines = bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		lines++
	}
	return lines, false, digest, nil
}

func digestFile(path string) (digest string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
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

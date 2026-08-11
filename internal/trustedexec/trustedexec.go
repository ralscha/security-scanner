package trustedexec

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Executable struct {
	Path string
	Env  []string
}

func Resolve(name, protectedRoot string) (Executable, error) {
	root, err := canonicalPath(protectedRoot)
	if err != nil {
		return Executable{}, fmt.Errorf("resolve protected root: %w", err)
	}
	entries := trustedPathEntries(root)
	for _, entry := range entries {
		for _, candidateName := range candidateNames(name) {
			candidate := filepath.Join(entry, candidateName)
			canonical, err := filepath.EvalSymlinks(candidate)
			if err != nil || within(root, canonical) {
				continue
			}
			info, err := os.Stat(canonical)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
				continue
			}
			return Executable{Path: canonical, Env: sanitizedEnvironment(entries)}, nil
		}
	}
	return Executable{}, fmt.Errorf("%s is not available on a trusted PATH", name)
}

func WithoutVariables(environment []string, names ...string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		remove := false
		for _, name := range names {
			if strings.EqualFold(key, name) {
				remove = true
				break
			}
		}
		if !remove {
			result = append(result, entry)
		}
	}
	return result
}

func trustedPathEntries(root string) []string {
	entries := make([]string, 0)
	seen := make(map[string]struct{})
	for _, entry := range filepath.SplitList(os.Getenv("PATH")) {
		if entry == "" || !filepath.IsAbs(entry) {
			continue
		}
		canonical, err := filepath.EvalSymlinks(entry)
		if err != nil || within(root, canonical) {
			continue
		}
		key := canonical
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, canonical)
	}
	return entries
}

func candidateNames(name string) []string {
	if runtime.GOOS != "windows" {
		return []string{name}
	}
	extension := strings.ToLower(filepath.Ext(name))
	if extension == ".exe" || extension == ".com" {
		return []string{name}
	}
	return []string{name + ".exe", name + ".com"}
}

func sanitizedEnvironment(entries []string) []string {
	environment := WithoutVariables(os.Environ(), "PATH")
	return append(environment, "PATH="+strings.Join(entries, string(os.PathListSeparator)))
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return canonical, nil
	}
	return absolute, nil
}

func within(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

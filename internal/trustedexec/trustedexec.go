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
		if entry == "" {
			continue
		}
		absolute, err := filepath.Abs(entry)
		if err != nil {
			continue
		}
		canonical, err := filepath.EvalSymlinks(absolute)
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

var gitRepositoryEnvironment = map[string]struct{}{
	"GIT_DIR": {}, "GIT_WORK_TREE": {}, "GIT_INDEX_FILE": {}, "GIT_OBJECT_DIRECTORY": {},
	"GIT_ALTERNATE_OBJECT_DIRECTORIES": {}, "GIT_COMMON_DIR": {}, "GIT_REPLACE_REF_BASE": {},
	"GIT_CEILING_DIRECTORIES": {}, "GIT_DISCOVERY_ACROSS_FILESYSTEM": {}, "GIT_GRAFT_FILE": {},
	"GIT_IMPLICIT_WORK_TREE": {}, "GIT_NAMESPACE": {}, "GIT_NO_REPLACE_OBJECTS": {},
	"GIT_PREFIX": {}, "GIT_SHALLOW_FILE": {},
}

// GitEnvironment removes repository redirection and protocol overrides from a
// child environment. Configuration is retained only for metadata-only Git
// commands such as rev-parse; repository-reading commands receive no GIT_*
// configuration so hooks and filters cannot inherit credentials.
func GitEnvironment(environment []string, preserveConfiguration bool) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		normalized := strings.ToUpper(key)
		_, repositoryOverride := gitRepositoryEnvironment[normalized]
		if repositoryOverride || normalized == "GIT_ALLOW_PROTOCOL" ||
			(!preserveConfiguration && strings.HasPrefix(normalized, "GIT_")) {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "GIT_ALLOW_PROTOCOL=")
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

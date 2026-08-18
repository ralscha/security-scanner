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
	pathLike := strings.ContainsAny(name, `/\`)
	unsafeEntries := make(map[string]struct{})
	executable := ""
	for _, candidate := range executableCandidates(name, entries, pathLike, runtime.GOOS == "windows") {
		canonical, err := filepath.EvalSymlinks(candidate.path)
		if err != nil {
			continue
		}
		if within(root, canonical) {
			if candidate.entry != "" {
				unsafeEntries[candidate.entry] = struct{}{}
			}
			continue
		}
		if !candidate.runnable {
			continue
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
			continue
		}
		if executable == "" {
			executable = canonical
		}
	}
	if executable != "" {
		return Executable{Path: executable, Env: sanitizedEnvironment(entries, unsafeEntries)}, nil
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

type executableCandidate struct {
	entry    string
	path     string
	runnable bool
}

type executableSuffix struct {
	value    string
	runnable bool
}

func executableCandidates(name string, entries []string, pathLike, windows bool) []executableCandidate {
	suffixes := executableSuffixes(name, pathLike, windows)
	if pathLike {
		candidates := make([]executableCandidate, 0, len(suffixes))
		for _, suffix := range suffixes {
			path, err := filepath.Abs(name + suffix.value)
			if err == nil {
				candidates = append(candidates, executableCandidate{path: path, runnable: suffix.runnable})
			}
		}
		return candidates
	}
	candidates := make([]executableCandidate, 0, len(entries)*len(suffixes))
	for _, entry := range entries {
		for _, suffix := range suffixes {
			candidates = append(candidates, executableCandidate{
				entry: entry, path: filepath.Join(entry, name+suffix.value), runnable: suffix.runnable,
			})
		}
	}
	return candidates
}

func executableSuffixes(name string, pathLike, windows bool) []executableSuffix {
	if !windows {
		return []executableSuffix{{runnable: true}}
	}
	extension := strings.ToLower(filepath.Ext(name))
	if extension == ".exe" || extension == ".com" {
		return []executableSuffix{{runnable: true}}
	}
	if pathLike {
		if extension == "" {
			return []executableSuffix{{value: ".exe", runnable: true}}
		}
		return []executableSuffix{{}}
	}
	return []executableSuffix{
		{value: ".exe", runnable: true},
		{value: ".com", runnable: true},
		{value: ".bat"},
		{value: ".cmd"},
		{},
	}
}

func sanitizedEnvironment(entries []string, unsafe map[string]struct{}) []string {
	environment := WithoutVariables(os.Environ(), "PATH")
	trusted := make([]string, 0, len(entries))
	for _, entry := range entries {
		if _, excluded := unsafe[entry]; !excluded {
			trusted = append(trusted, entry)
		}
	}
	return append(environment, "PATH="+strings.Join(trusted, string(os.PathListSeparator)))
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

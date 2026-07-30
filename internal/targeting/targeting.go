package targeting

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Selector struct {
	Paths       []string
	DiffRef     string
	WorkingTree bool
}

type Resolution struct {
	Mode  string   `json:"mode"`
	Ref   string   `json:"ref,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

func (s Selector) Validate() error {
	modes := 0
	if len(s.Paths) > 0 {
		modes++
	}
	if strings.TrimSpace(s.DiffRef) != "" {
		modes++
	}
	if s.WorkingTree {
		modes++
	}
	if modes > 1 {
		return fmt.Errorf("--path, --diff, and --working-tree are mutually exclusive")
	}
	return nil
}

func Resolve(ctx context.Context, root string, selector Selector) (Resolution, error) {
	if err := selector.Validate(); err != nil {
		return Resolution{}, err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolve target: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolve target symlinks: %w", err)
	}
	if len(selector.Paths) > 0 {
		paths, err := resolvePaths(absRoot, selector.Paths)
		return Resolution{Mode: "path", Paths: paths}, err
	}
	if ref := strings.TrimSpace(selector.DiffRef); ref != "" {
		paths, err := gitPaths(ctx, absRoot, "diff", ref)
		return Resolution{Mode: "diff", Ref: ref, Paths: paths}, err
	}
	if selector.WorkingTree {
		paths, err := gitPaths(ctx, absRoot, "working-tree", "")
		return Resolution{Mode: "working_tree", Paths: paths}, err
	}
	return Resolution{Mode: "all"}, nil
}

func resolvePaths(root string, values []string) ([]string, error) {
	paths := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("--path cannot be empty")
		}
		candidate := value
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(root, candidate)
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return nil, fmt.Errorf("resolve path %q: %w", value, err)
		}
		rel, err := filepath.Rel(root, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("path %q is outside target", value)
		}
		rel = filepath.ToSlash(rel)
		if _, ok := seen[rel]; !ok {
			seen[rel] = struct{}{}
			paths = append(paths, rel)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func gitPaths(ctx context.Context, root, mode, ref string) ([]string, error) {
	gitRootBytes, err := runGit(ctx, root, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("target is not in a git worktree: %w", err)
	}
	gitRoot, err := filepath.EvalSymlinks(strings.TrimSpace(string(gitRootBytes)))
	if err != nil {
		return nil, fmt.Errorf("resolve git root: %w", err)
	}
	var outputs [][]byte
	if mode == "diff" {
		output, err := runGit(ctx, gitRoot, "diff", "--name-only", "-z", ref, "--")
		if err != nil {
			return nil, fmt.Errorf("resolve diff %q: %w", ref, err)
		}
		outputs = append(outputs, output)
	} else {
		tracked, err := runGit(ctx, gitRoot, "diff", "--name-only", "-z", "HEAD", "--")
		if err != nil {
			return nil, fmt.Errorf("resolve working tree changes: %w", err)
		}
		untracked, err := runGit(ctx, gitRoot, "ls-files", "--others", "--exclude-standard", "-z", "--")
		if err != nil {
			return nil, fmt.Errorf("resolve untracked files: %w", err)
		}
		outputs = append(outputs, tracked, untracked)
	}
	return pathsUnderRoot(root, gitRoot, outputs), nil
}

func pathsUnderRoot(root, gitRoot string, outputs [][]byte) []string {
	seen := make(map[string]struct{})
	for _, output := range outputs {
		for raw := range bytes.SplitSeq(output, []byte{0}) {
			if len(raw) == 0 {
				continue
			}
			absolute := filepath.Join(gitRoot, filepath.FromSlash(string(raw)))
			if _, err := os.Stat(absolute); err != nil {
				continue
			}
			rel, err := filepath.Rel(root, absolute)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			seen[filepath.ToSlash(rel)] = struct{}{}
		}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func runGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	output, err := command.Output()
	if err == nil {
		return output, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(exitErr.Stderr)))
	}
	return nil, err
}

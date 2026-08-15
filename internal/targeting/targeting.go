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

	"security-scanner/internal/trustedexec"
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
		base, err := resolveGitCommit(ctx, gitRoot, ref)
		if err != nil {
			return nil, fmt.Errorf("resolve diff %q: %w", ref, err)
		}
		head, err := resolveGitCommit(ctx, gitRoot, "HEAD")
		if err != nil {
			return nil, fmt.Errorf("resolve checkout HEAD: %w", err)
		}
		if err := validateCommittedDiffCheckout(ctx, gitRoot); err != nil {
			return nil, err
		}
		output, err := runGit(ctx, gitRoot, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", base, head, "--")
		if err != nil {
			return nil, fmt.Errorf("resolve diff %q: %w", ref, err)
		}
		outputs = append(outputs, output)
	} else {
		tracked, err := runGit(ctx, gitRoot, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "HEAD", "--")
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

func resolveGitCommit(ctx context.Context, gitRoot, ref string) (string, error) {
	output, err := runGit(ctx, gitRoot, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(output))
	if commit == "" {
		return "", fmt.Errorf("git returned an empty commit ID")
	}
	return commit, nil
}

func validateCommittedDiffCheckout(ctx context.Context, gitRoot string) error {
	status, err := runGit(ctx, gitRoot, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return fmt.Errorf("inspect committed-diff checkout: %w", err)
	}
	if len(status) != 0 {
		return fmt.Errorf("committed-diff scans require a clean repository checkout; commit, stash, or remove local changes and retry")
	}

	tracked, err := runGit(ctx, gitRoot, "ls-files", "-t", "-z")
	if err != nil {
		return fmt.Errorf("inspect committed-diff checkout: %w", err)
	}
	for entry := range bytes.SplitSeq(tracked, []byte{0}) {
		if bytes.HasPrefix(entry, []byte("S ")) {
			return fmt.Errorf("committed-diff scans require a full repository checkout; sparse checkouts are not supported")
		}
	}
	return nil
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
	git, err := trustedexec.Resolve("git", dir)
	if err != nil {
		return nil, err
	}
	preserveConfiguration := len(args) > 0 && args[0] == "rev-parse"
	environment := trustedexec.GitEnvironment(git.Env, preserveConfiguration)
	environment = trustedexec.WithoutVariables(environment, "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS")
	commandArgs := append([]string{"-c", "core.fsmonitor=false", "-C", dir}, args...)
	command := exec.CommandContext(ctx, git.Path, commandArgs...)
	command.Env = append(environment, "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	output, err := command.Output()
	if err == nil {
		return output, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(exitErr.Stderr)))
	}
	return nil, err
}

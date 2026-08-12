//go:build !windows && !linux

package knowledgebase

import "os"

func fileIdentity(_ *os.File) (string, error) {
	return "", nil
}

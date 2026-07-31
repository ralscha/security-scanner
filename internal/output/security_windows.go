//go:build windows

package output

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func preparePrivateDirectory(path string, _, _ bool) error {
	return installPrivateACL(path, true)
}

func preparePrivateFile(path string) error {
	return installPrivateACL(path, false)
}

// Planning is read-only. The protected ACL is installed before the model is
// called and then verified on every guarded use.
func validatePrivateDirectoryForPlanning(info os.FileInfo, path string) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output directory must be a non-symlink directory: %s", path)
	}
	return nil
}

func validatePrivateDirectory(info os.FileInfo, path string) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private directory must be a non-symlink directory: %s", path)
	}
	return validatePrivateACL(path)
}

func validatePrivateFile(info os.FileInfo, path string) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private file must be a non-symlink regular file: %s", path)
	}
	return validatePrivateACL(path)
}

func installPrivateACL(path string, directory bool) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("identify current Windows user: %w", err)
	}
	var pinner runtime.Pinner
	pinner.Pin(sid)
	defer pinner.Unpin()
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build private Windows ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		sid,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("install private Windows ACL: %w", err)
	}
	return validatePrivateACL(path)
}

func validatePrivateACL(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("identify current Windows user: %w", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect private Windows ACL: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(sid) {
		return fmt.Errorf("private Windows path must be owned by the current user: %s", path)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("inspect private Windows ACL protection: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private Windows path must not inherit access rules: %s", path)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("private Windows path must have an explicit access list: %s", path)
	}
	if dacl.AceCount == 0 {
		return fmt.Errorf("private Windows path must grant access to the current user: %s", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return fmt.Errorf("inspect private Windows access rule: %w", err)
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !aceSID.Equals(sid) {
			return fmt.Errorf("private Windows path grants access to another identity: %s", path)
		}
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func validateSecureAncestry(string) error { return nil }

func sameCanonicalPath(left, right string) bool {
	rel, err := filepath.Rel(filepath.Clean(left), filepath.Clean(right))
	return err == nil && rel == "."
}

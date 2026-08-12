package knowledgebase

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

func fileIdentity(file *os.File) (string, error) {
	var info fileIDInfo
	if err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()),
		windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return "", err
	}
	return fmt.Sprintf("%016x:%x", info.VolumeSerialNumber, info.FileID), nil
}

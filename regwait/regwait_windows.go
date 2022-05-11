// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file of Go.
// Copied from https://go-review.googlesource.com/c/sys/+/236681
// Filter fixes Copyright 2021 Jeremy Rand; same license as original.

package regwait

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var _ unsafe.Pointer

var (
	modadvapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	procRegNotifyChangeKeyValue = modadvapi32.NewProc("RegNotifyChangeKeyValue")
)

const (
	Subkey    = 0x1
	Attribute = 0x2
	Value     = 0x4
	Security  = 0x8
)

func regNotifyChangeKeyValue(key syscall.Handle, watchSubtree bool,
	notifyFilter uint32, event syscall.Handle, async bool,
) (regerrno error) {
	var _p0 uint32
	if watchSubtree {
		_p0 = 1
	} else {
		_p0 = 0
	}

	var _p1 uint32

	if async {
		_p1 = 1
	} else {
		_p1 = 0
	}

	r0, _, _ := syscall.Syscall6(procRegNotifyChangeKeyValue.Addr(), 5,
		uintptr(key), uintptr(_p0), uintptr(notifyFilter), uintptr(event),
		uintptr(_p1), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}

	return
}

// WaitChange waits for k to change using RegNotifyChangeKeyValue.
// The subtree parameter is whether subtrees should also be watched.
func WaitChange(k registry.Key, subtree bool, filter uint32) error {
	return regNotifyChangeKeyValue(syscall.Handle(k), subtree, filter, 0, false)
}

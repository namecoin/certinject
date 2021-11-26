//go:build windows
// +build windows

package certinject

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

type registryKeyNamesTestCase struct {
	Name     string // for logs
	Physical string // from user flag
	Logical  string // from user flag
	Key      string // registry
	Base     registry.Key
}

func registryKeyNamesTestData() []registryKeyNamesTestCase {
	hkcu := registry.CURRENT_USER
	hklm := registry.LOCAL_MACHINE

	return []registryKeyNamesTestCase{
		{"system+root", "system", "Root", `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`, hklm},
		{"system+CA", "system", "CA", `SOFTWARE\Microsoft\SystemCertificates\CA\Certificates`, hklm},
		{"system+My", "system", "My", `SOFTWARE\Microsoft\SystemCertificates\My\Certificates`, hklm},
		{"system+Trust", "system", "Trust", `SOFTWARE\Microsoft\SystemCertificates\Trust\Certificates`, hklm},
		{"system+Disallowed", "system", "Disallowed", `SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates`, hklm},
		{"user+root", "current-user", "Root", `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`, hkcu},
		{"user+CA", "current-user", "CA", `SOFTWARE\Microsoft\SystemCertificates\CA\Certificates`, hkcu},
		{"user+My", "current-user", "My", `SOFTWARE\Microsoft\SystemCertificates\My\Certificates`, hkcu},
		{"user+Trust", "current-user", "Trust", `SOFTWARE\Microsoft\SystemCertificates\Trust\Certificates`, hkcu},
		{"enterprise+root", "enterprise", "Root", `SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates`, hklm},
		{"enterprise+CA", "enterprise", "CA", `SOFTWARE\Microsoft\EnterpriseCertificates\CA\Certificates`, hklm},
		{"enterprise+My", "enterprise", "My", `SOFTWARE\Microsoft\EnterpriseCertificates\My\Certificates`, hklm},
		{"enterprise+Trust", "enterprise", "Trust", `SOFTWARE\Microsoft\EnterpriseCertificates\Trust\Certificates`, hklm},
		{"group+root", "group-policy", "Root", `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates`, hklm},
		{"group+CA", "group-policy", "CA", `SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates`, hklm},
		{"group+My", "group-policy", "My", `SOFTWARE\Policies\Microsoft\SystemCertificates\My\Certificates`, hklm},
		{"group+Trust", "group-policy", "Trust", `SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\Certificates`, hklm},
	}
}

func TestRegistryKeyNames(t *testing.T) {
	hkcu := registry.CURRENT_USER
	hklm := registry.LOCAL_MACHINE
	tests := registryKeyNamesTestData()

	for _, testCase := range tests {
		store, ok := cryptoAPIStores[testCase.Physical]
		if !ok {
			t.Errorf("test %q is invalid (store not defined)", testCase.Physical)

			continue
		}

		if err := cryptoAPIFlagLogicalStoreName.CfSetValue(testCase.Logical); err != nil {
			t.Errorf("test %q: %v", testCase.Name, err)

			continue
		}

		key := store.Key()
		if key != testCase.Key {
			t.Errorf("test %q: expected key to be %q, got %q", testCase.Name, testCase.Key, key)

			continue
		}

		base2str := func(t *testing.T, rkey registry.Key) string {
			switch rkey {
			case hkcu:
				return "HKCU"
			case hklm:
				return "HKLM"
			default:
				t.Errorf("expected valid registry key, got: %v", rkey)
				t.FailNow()

				return ""
			}
		}

		base := store.Base
		if base != testCase.Base {
			t.Errorf("test %q: expected base to be %v, got %v", testCase.Name, base2str(t, testCase.Base), base2str(t, base))

			continue
		}

		t.Logf("[PASS] test %q: %s\\%s", testCase.Name, base2str(t, base), key)
	}
}

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
	cu := registry.CURRENT_USER
	lm := registry.LOCAL_MACHINE

	return []registryKeyNamesTestCase{
		{"system+root", "system", "Root", `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`, lm},
		{"system+CA", "system", "CA", `SOFTWARE\Microsoft\SystemCertificates\CA\Certificates`, lm},
		{"system+My", "system", "My", `SOFTWARE\Microsoft\SystemCertificates\My\Certificates`, lm},
		{"system+Trust", "system", "Trust", `SOFTWARE\Microsoft\SystemCertificates\Trust\Certificates`, lm},
		{"system+Disallowed", "system", "Disallowed", `SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates`, lm},
		{"user+root", "current-user", "Root", `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`, cu},
		{"user+CA", "current-user", "CA", `SOFTWARE\Microsoft\SystemCertificates\CA\Certificates`, cu},
		{"user+My", "current-user", "My", `SOFTWARE\Microsoft\SystemCertificates\My\Certificates`, cu},
		{"user+Trust", "current-user", "Trust", `SOFTWARE\Microsoft\SystemCertificates\Trust\Certificates`, cu},
		{"enterprise+root", "enterprise", "Root", `SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates`, lm},
		{"enterprise+CA", "enterprise", "CA", `SOFTWARE\Microsoft\EnterpriseCertificates\CA\Certificates`, lm},
		{"enterprise+My", "enterprise", "My", `SOFTWARE\Microsoft\EnterpriseCertificates\My\Certificates`, lm},
		{"enterprise+Trust", "enterprise", "Trust", `SOFTWARE\Microsoft\EnterpriseCertificates\Trust\Certificates`, lm},
		{"group+root", "group-policy", "Root", `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates`, lm},
		{"group+CA", "group-policy", "CA", `SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates`, lm},
		{"group+My", "group-policy", "My", `SOFTWARE\Policies\Microsoft\SystemCertificates\My\Certificates`, lm},
		{"group+Trust", "group-policy", "Trust", `SOFTWARE\Policies\Microsoft\SystemCertificates\Trust\Certificates`, lm},
	}
}

func TestRegistryKeyNames(t *testing.T) {
	cu := registry.CURRENT_USER
	lm := registry.LOCAL_MACHINE
	tests := registryKeyNamesTestData()

	for _, tc := range tests {
		store, ok := cryptoAPIStores[tc.Physical]
		if !ok {
			t.Errorf("test %q is invalid (store not defined)", tc.Physical)

			continue
		}

		if err := cryptoAPIFlagLogicalStoreName.CfSetValue(tc.Logical); err != nil {
			t.Errorf("test %q: %v", tc.Name, err)

			continue
		}

		key := store.Key()
		if key != tc.Key {
			t.Errorf("test %q: expected key to be %q, got %q", tc.Name, tc.Key, key)

			continue
		}

		base2str := func(t *testing.T, r registry.Key) string {
			switch r {
			case cu:
				return "HKCU"
			case lm:
				return "HKLM"
			default:
				t.Errorf("expected valid registry key, got: %v", r)
				t.FailNow()

				return ""
			}
		}

		base := store.Base
		if base != tc.Base {
			t.Errorf("test %q: expected base to be %v, got %v", tc.Name, base2str(t, tc.Base), base2str(t, base))

			continue
		}

		t.Logf("[PASS] test %q: %s\\%s", tc.Name, base2str(t, base), key)
	}
}

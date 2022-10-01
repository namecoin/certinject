package certinject

import (
	// #nosec G505
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"gopkg.in/hlandau/easyconfig.v1/cflag"

	"github.com/namecoin/certinject/certblob"
	"github.com/namecoin/certinject/regwait"
)

var (
	cryptoAPIFlagGroup            = cflag.NewGroup(flagGroup, "capi")
	cryptoAPIFlagLogicalStoreName = cflag.String(cryptoAPIFlagGroup, "logical-store", "Root",
		"Name of CryptoAPI logical store to inject certificate into. Consider: AuthRoot, Root, Trust, CA, My, Disallowed")
	cryptoAPIFlagPhysicalStoreName = cflag.String(cryptoAPIFlagGroup, "physical-store", "system",
		"Scope of CryptoAPI certificate store. Valid choices: current-user, system, enterprise, group-policy")
	cryptoAPIFlagReset = cflag.Bool(cryptoAPIFlagGroup, "reset", false,
		"Delete any existing properties of this certificate before applying any new ones")
	searchSHA1 = cflag.String(cryptoAPIFlagGroup, "search-sha1", "",
		"Search the store for an existing certificate with this SHA1 hash "+
			"(uppercase hex) instead of loading a certificate from a file")
	allCerts = cflag.Bool(cryptoAPIFlagGroup, "all-certs", false,
		"Apply operations to all certificates in the specified store")
	watch = cflag.Bool(cryptoAPIFlagGroup, "watch", false,
		"Continuously re-apply operations whenever the specified store updates")
	ekuFlagGroup = cflag.NewGroup(cryptoAPIFlagGroup, "eku")
	ekuAny       = cflag.Bool(ekuFlagGroup, "any", false, "Any purpose")
	ekuServer    = cflag.Bool(ekuFlagGroup, "server", false,
		"Server authentication")
	ekuClient = cflag.Bool(ekuFlagGroup, "client", false,
		"Client authentication")
	ekuCode  = cflag.Bool(ekuFlagGroup, "code", false, "Code signing")
	ekuEmail = cflag.Bool(ekuFlagGroup, "email", false,
		"Secure email")
	ekuIPSECEndSystem = cflag.Bool(ekuFlagGroup, "ipsec-end-system", false,
		"IP security end system")
	ekuIPSECTunnel = cflag.Bool(ekuFlagGroup, "ipsec-tunnel", false,
		"IP security tunnel termination")
	ekuIPSECUser = cflag.Bool(ekuFlagGroup, "ipsec-user", false,
		"IP security user")
	ekuTime = cflag.Bool(ekuFlagGroup, "time", false, "Time stamping")
	ekuOCSP = cflag.Bool(ekuFlagGroup, "ocsp", false, "OCSP signing")
	// We intentionally do not support "server-gated crypto" / "international
	// step-up" EKU values, because 90's-era export-grade crypto can go shove
	// its reproductive organs in a beehive.
	ekuMSCodeCom = cflag.Bool(ekuFlagGroup, "ms-code-com", false,
		"Microsoft commercial code signing")
	ekuMSCodeKernel = cflag.Bool(ekuFlagGroup, "ms-code-kernel", false,
		"Microsoft kernel-mode code signing")
	nameConstraintsFlagGroup    = cflag.NewGroup(cryptoAPIFlagGroup, "nc")
	nameConstraintsPermittedDNS = cflag.String(nameConstraintsFlagGroup,
		"permitted-dns", "", "Permitted DNS domain")
	nameConstraintsExcludedDNS = cflag.String(nameConstraintsFlagGroup,
		"excluded-dns", "", "Excluded DNS domain")
	nameConstraintsPermittedIP = cflag.String(nameConstraintsFlagGroup,
		"permitted-ip", "", "Permitted IP range")
	nameConstraintsExcludedIP = cflag.String(nameConstraintsFlagGroup,
		"excluded-ip", "", "Excluded IP range")
	nameConstraintsPermittedEmail = cflag.String(nameConstraintsFlagGroup,
		"permitted-email", "", "Permitted email address")
	nameConstraintsExcludedEmail = cflag.String(nameConstraintsFlagGroup,
		"excluded-email", "", "Excluded email address")
	nameConstraintsPermittedURI = cflag.String(nameConstraintsFlagGroup,
		"permitted-uri", "", "Permitted URI domain")
	nameConstraintsExcludedURI = cflag.String(nameConstraintsFlagGroup,
		"excluded-uri", "", "Excluded URI domain")
	setMagicName = cflag.String(cryptoAPIFlagGroup, "set-magic-name", "",
		"Set a magic tag with this name")
	setMagicData = cflag.Int(cryptoAPIFlagGroup, "set-magic-data", 1,
		"Set a magic tag with this data")
	skipMagicName = cflag.String(cryptoAPIFlagGroup, "skip-magic-name", "",
		"Don't touch certificates with this magic tag name")
	skipMagicData = cflag.Int(cryptoAPIFlagGroup, "skip-magic-data", 1,
		"Don't touch certificates with this magic tag data")
	expirableMagicName = cflag.String(cryptoAPIFlagGroup,
		"expirable-magic-name", "",
		"Remove certificates with this magic tag name if they are too old "+
			"(see -certstore.expire flag)")
	expirableMagicData = cflag.Int(cryptoAPIFlagGroup, "expirable-magic-data",
		1, "Remove certificates with this magic tag data if they are too old "+
			"(see -certstore.expire flag)")
)

var (
	ErrInjectCerts          = errors.New("error injecting certs")
	ErrEnumerateCerts       = fmt.Errorf("error enumerating certs: %w", ErrInjectCerts)
	ErrInvalidPhysicalStore = fmt.Errorf("invalid choice for physical store "+
		"(consider current-user, system, enterprise, group-policy): %w",
		ErrEnumerateCerts)
	ErrGetInitialBlob = fmt.Errorf("error getting initial blob: %w", ErrInjectCerts)
	ErrEditBlob       = fmt.Errorf("error editing blob: %w", ErrInjectCerts)
	ErrSetMagic       = fmt.Errorf("error setting magic tag: %w", ErrInjectCerts)
)

// cryptoAPIStores consists of every implemented store.
// When adding a new one, the `%s` variable is optional.
// If `%s` exists in the Logical string, it is replaced with the value of
// the -logical-store flag.
var cryptoAPIStores = map[string]Store{
	"current-user": {registry.CURRENT_USER, `SOFTWARE\Microsoft\SystemCertificates`, `%s\Certificates`},
	"system":       {registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\SystemCertificates`, `%s\Certificates`},
	"enterprise":   {registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EnterpriseCertificates`, `%s\Certificates`},
	"group-policy": {registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\SystemCertificates`, `%s\Certificates`},
}

// Store is used to generate a registry key to open a certificate store in the Windows Registry.
type Store struct {
	Base     registry.Key
	Physical string
	Logical  string // may contain a %s, in which it would be replaced by the -logical-store flag
}

// String returns a human readable string (only useful for debug logs).
func (s Store) String() string {
	return fmt.Sprintf(`%s\%s\`+s.Logical, s.Base, s.Physical, cryptoAPIFlagLogicalStoreName.Value())
}

// Key generates the registry key for use in opening the store.
func (s Store) Key() string {
	return fmt.Sprintf(`%s\`+s.Logical, s.Physical, cryptoAPIFlagLogicalStoreName.Value())
}

// cryptoAPINameToStore returns a Store for the specified name.  Returns an
// error if the specified name is invalid.
func cryptoAPINameToStore(name string) (Store, error) {
	store, ok := cryptoAPIStores[name]
	if !ok {
		return Store{}, ErrInvalidPhysicalStore
	}

	return store, nil
}

func allFingerprintsInStore(registryBase registry.Key, storeKey string) ([]string, error) {
	// Open up the cert store.
	certStoreKey, err := registry.OpenKey(registryBase, storeKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("%s: couldn't open cert store: %w", err, ErrEnumerateCerts)
	}
	defer certStoreKey.Close()

	fingerprintHexUpperList, err := certStoreKey.ReadSubKeyNames(0)
	if err != nil {
		return nil, fmt.Errorf("%s: couldn't list certs in cert store: %w", err, ErrEnumerateCerts)
	}

	return fingerprintHexUpperList, nil
}

func readInputBlob(derBytes []byte, registryBase registry.Key, path string) (certblob.Blob, error) {
	if cryptoAPIFlagReset.Value() && derBytes != nil {
		// We already know the cert preimage, and we're excluding any
		// properties, so no need to check the registry.
		return certblob.Blob{certblob.CertContentCertPropID: derBytes}, nil
	}

	// We need to look up either the cert preimage or the properties via
	// the registry.

	// Open up the cert key.
	certKey, err := registry.OpenKey(registryBase, path, registry.QUERY_VALUE)
	if err != nil && derBytes != nil {
		// We can't read the blob, but we do already know the cert
		// preimage, so create a default blob based on that preimage.
		return certblob.Blob{certblob.CertContentCertPropID: derBytes}, nil
	}
	defer certKey.Close()

	inputBlobBytes, _, err := certKey.GetBinaryValue("Blob")
	if err != nil {
		return nil, fmt.Errorf("%s: couldn't read blob value: %w", err, ErrGetInitialBlob)
	}

	blob, err := certblob.ParseBlob(inputBlobBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: couldn't parse blob: %w", err, ErrGetInitialBlob)
	}

	return blob, nil
}

func injectCertCryptoAPI(derBytes []byte) {
	store, err := cryptoAPINameToStore(cryptoAPIFlagPhysicalStoreName.Value())
	if err != nil {
		log.Errorf("error: %s", err.Error())

		return
	}

	registryBase := store.Base
	storeKey := store.Key()

	var storeNotifyKey registry.Key

	if watch.Value() {
		// Open up the cert store.
		storeNotifyKey, err = registry.OpenKey(registryBase, storeKey, registry.NOTIFY)
		if err != nil {
			log.Errorf("%s: couldn't open cert store: %w", err, ErrEnumerateCerts)

			return
		}
		defer storeNotifyKey.Close()
	}

	injectCertLoopCryptoAPI(derBytes, registryBase, storeKey, storeNotifyKey)
}

func injectCertLoopCryptoAPI(derBytes []byte, registryBase registry.Key, storeKey string, storeNotifyKey registry.Key) {
	ready := false

	for {
		injectCertOnceCryptoAPI(derBytes, registryBase, storeKey)

		if !watch.Value() {
			break
		}

		// As per Windows API docs, the first call to RegNotifyChangeKeyValue
		// behaves differently from subsequent calls.  The first call waits for
		// an event that occurred after the call was made; all subsequent calls
		// wait for an event that occurred after the previous reported event.
		// The first call does NOT report events that occurred between the
		// opening of the key and the first call, which is what would be sane.
		// Thus, we have a race condition, where if an event happens between
		// opening the key and the first call, that event will be dropped.
		// Thus, as a stupid workaround, we set up a goroutine to reapply any
		// requested cert store operations ~3 seconds after the first call, so
		// that if the race condition was hit, it will be automatically fixed
		// after ~3 seconds.  I know this is stupid.  Blame Microsoft, not me.
		if !ready {
			go func() {
				time.Sleep(3 * time.Second)
				injectCertOnceCryptoAPI(derBytes, registryBase, storeKey)

				log.Info("Registry is ready")

				ready = true
			}()
		}

		log.Info("Waiting for registry change...")

		err := regwait.WaitChange(storeNotifyKey, true, regwait.Subkey|regwait.Value)
		if err != nil {
			log.Errorf("%s: couldn't watch cert store", err)
		}
	}
}

func injectCertOnceCryptoAPI(derBytes []byte, registryBase registry.Key, storeKey string) {
	fingerprintHexUpperList := []string{}

	var err error

	if allCerts.Value() {
		derBytes = nil

		fingerprintHexUpperList, err = allFingerprintsInStore(registryBase, storeKey)
		if err != nil {
			log.Errorf("Couldn't enumerate certificates in store: %s", err)

			return
		}
	}

	if len(fingerprintHexUpperList) == 0 && searchSHA1.Value() != "" {
		fingerprintHexUpperList = append(fingerprintHexUpperList, searchSHA1.Value())
	}

	if len(fingerprintHexUpperList) == 0 {
		if derBytes == nil {
			log.Errorf("No cert specified")

			return
		}

		// Windows CryptoAPI uses the SHA-1 fingerprint to identify a cert.
		// This is probably a Bad Thing (TM) since SHA-1 is weak.
		// However, that's Microsoft's problem to fix, not ours.
		fingerprint := sha1.Sum(derBytes) // #nosec G401

		// Windows CryptoAPI uses a hex string to represent the fingerprint.
		fingerprintHex := hex.EncodeToString(fingerprint[:])

		// Windows CryptoAPI uses uppercase hex strings
		fingerprintHexUpperList = append(fingerprintHexUpperList, strings.ToUpper(fingerprintHex))
	}

	for _, fingerprintHexUpper := range fingerprintHexUpperList {
		injectSingleCertCryptoAPI(derBytes, fingerprintHexUpper, registryBase, storeKey)
	}
}

func injectSingleCertCryptoAPI(derBytes []byte, fingerprintHexUpper string,
	registryBase registry.Key, storeKey string,
) {
	// Construct the input Blob
	blob, err := readInputBlob(derBytes, registryBase, storeKey+`\`+fingerprintHexUpper)
	if err != nil {
		log.Errorf("Couldn't read input blob: %s", err)

		return
	}

	err = editBlob(blob)
	if err != nil {
		log.Errorf("Couldn't edit blob: %s", err)

		return
	}

	// Marshal the Blob
	blobBytes, err := blob.Marshal()
	if err != nil {
		log.Errorf("Couldn't marshal cert blob: %s", err)

		return
	}

	// Open up the cert store.
	certStoreKey, err := registry.OpenKey(registryBase, storeKey, registry.ALL_ACCESS)
	if err != nil {
		log.Errorf("Couldn't open cert store: %s", err)

		return
	}
	defer certStoreKey.Close()

	// Create the registry key in which we will store the cert.
	// The 2nd result of CreateKey is openedExisting, which tells us if the cert already existed.
	// This doesn't matter to us.  If true, the "last modified" metadata won't update,
	// but we delete and recreate the magic value inside it as a workaround.
	certKey, _, err := registry.CreateKey(certStoreKey, fingerprintHexUpper, registry.ALL_ACCESS)
	if err != nil {
		log.Errorf("Couldn't create registry key for certificate: %s", err)

		return
	}
	defer certKey.Close()

	// Check for magic value indicating we should skip this cert
	shouldSkip, _, err := certKey.GetIntegerValue(skipMagicName.Value())
	if err == nil && shouldSkip == uint64(skipMagicData.Value()) {
		// Magic value detected.  Skip.
		return
	}

	applyRegistryValues(certKey, blobBytes)
}

func applyRegistryValues(certKey registry.Key, blobBytes []byte) {
	var err error

	if setMagicName.Value() != "" {
		err = applyMagic(certKey)
		if err != nil {
			log.Errorf("Couldn't set magic registry value for certificate: %s", err)

			return
		}
	}

	// Create the registry value which holds the certificate.
	err = certKey.SetBinaryValue("Blob", blobBytes)
	if err != nil {
		log.Errorf("Couldn't set blob registry value for certificate: %s", err)

		return
	}
}

// Add an extra registry value that serves as a "magic tag".  This will be
// ignored by CryptoAPI, but can be recognized by software that knows to look
// for it.  Example uses:
//
//   - Indicating that a certificate is a Namecoin dehydrated certificate, and
//     should be deleted once it reaches a certain age to avoid leaving browsing
//     history in the registry.
//   - Indicating that a certificate is a Namecoin root certificate, and should
//     be exempt from a Namecoin name constraint exclusion that is applied to all
//     other root CA's.
func applyMagic(certKey registry.Key) error {
	// To satisfy the first example use case, we have to delete it before we
	// create it, so that we make sure that the "last modified" metadata gets
	// updated.  If an error occurs during deletion, we ignore it, since it
	// probably just means it wasn't there already.  In watch mode, we don't do
	// this, since it would cause an infinite loop.
	if !watch.Value() {
		_ = certKey.DeleteValue(setMagicName.Value())
	}

	err := certKey.SetDWordValue(setMagicName.Value(), uint32(setMagicData.Value()))
	if err != nil {
		return fmt.Errorf("%s: couldn't apply magic '%s'='%d': %w", err,
			setMagicName.Value(), uint32(setMagicData.Value()), ErrSetMagic)
	}

	return nil
}

func editBlob(blob certblob.Blob) error {
	err := editBlobEKU(blob)
	if err != nil {
		return err
	}

	err = editBlobNameConstraints(blob)
	if err != nil {
		return err
	}

	return nil
}

func editBlobEKU(blob certblob.Blob) error {
	ekus := buildEKUList()

	if len(ekus) == 0 {
		return nil
	}

	ekuTemplate := x509.Certificate{
		ExtKeyUsage: ekus,
	}

	ekuProperty, err := certblob.BuildExtKeyUsage(&ekuTemplate)
	if err != nil {
		return fmt.Errorf("%s: couldn't marshal extended key usage property: %w", err, ErrEditBlob)
	}

	blob.SetProperty(ekuProperty)

	return nil
}

func buildEKUList() []x509.ExtKeyUsage {
	ekus := []x509.ExtKeyUsage{}

	appendToEKUList(&ekus, ekuAny.Value(), x509.ExtKeyUsageAny)
	appendToEKUList(&ekus, ekuServer.Value(), x509.ExtKeyUsageServerAuth)
	appendToEKUList(&ekus, ekuClient.Value(), x509.ExtKeyUsageClientAuth)
	appendToEKUList(&ekus, ekuCode.Value(), x509.ExtKeyUsageCodeSigning)
	appendToEKUList(&ekus, ekuEmail.Value(), x509.ExtKeyUsageEmailProtection)
	appendToEKUList(&ekus, ekuIPSECEndSystem.Value(), x509.ExtKeyUsageIPSECEndSystem)
	appendToEKUList(&ekus, ekuIPSECTunnel.Value(), x509.ExtKeyUsageIPSECTunnel)
	appendToEKUList(&ekus, ekuIPSECUser.Value(), x509.ExtKeyUsageIPSECUser)
	appendToEKUList(&ekus, ekuTime.Value(), x509.ExtKeyUsageTimeStamping)
	appendToEKUList(&ekus, ekuOCSP.Value(), x509.ExtKeyUsageOCSPSigning)
	appendToEKUList(&ekus, ekuMSCodeCom.Value(), x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
	appendToEKUList(&ekus, ekuMSCodeKernel.Value(), x509.ExtKeyUsageMicrosoftKernelCodeSigning)

	return ekus
}

func appendToEKUList(ekus *[]x509.ExtKeyUsage, enable bool, usage x509.ExtKeyUsage) {
	if enable {
		*ekus = append(*ekus, usage)
	}
}

func editBlobNameConstraints(blob certblob.Blob) error {
	nameConstraintsTemplate, nameConstraintsValid, err := buildNameConstraintsTemplate()
	if err != nil {
		return err
	}

	if nameConstraintsValid {
		nameConstraintsProperty, err := certblob.BuildNameConstraints(nameConstraintsTemplate)
		if err != nil {
			return fmt.Errorf("%s: couldn't marshal name constraints property: %w", err, ErrEditBlob)
		}

		blob.SetProperty(nameConstraintsProperty)
	}

	return nil
}

func buildNameConstraintsTemplate() (*x509.Certificate, bool, error) {
	nameConstraintsValid := false
	nameConstraintsTemplate := x509.Certificate{}

	setNameConstraintsStrings(
		&nameConstraintsTemplate.PermittedDNSDomains,
		nameConstraintsPermittedDNS.Value(), &nameConstraintsValid)

	setNameConstraintsStrings(
		&nameConstraintsTemplate.ExcludedDNSDomains,
		nameConstraintsExcludedDNS.Value(), &nameConstraintsValid)

	err := setNameConstraintsIPRanges(
		&nameConstraintsTemplate.PermittedIPRanges,
		nameConstraintsPermittedIP.Value(), &nameConstraintsValid)
	if err != nil {
		return nil, false, fmt.Errorf("permitted: %w", err)
	}

	err = setNameConstraintsIPRanges(
		&nameConstraintsTemplate.ExcludedIPRanges,
		nameConstraintsExcludedIP.Value(), &nameConstraintsValid)
	if err != nil {
		return nil, false, fmt.Errorf("excluded: %w", err)
	}

	setNameConstraintsStrings(
		&nameConstraintsTemplate.PermittedEmailAddresses,
		nameConstraintsPermittedEmail.Value(), &nameConstraintsValid)

	setNameConstraintsStrings(
		&nameConstraintsTemplate.ExcludedEmailAddresses,
		nameConstraintsExcludedEmail.Value(), &nameConstraintsValid)

	setNameConstraintsStrings(
		&nameConstraintsTemplate.PermittedURIDomains,
		nameConstraintsPermittedURI.Value(), &nameConstraintsValid)

	setNameConstraintsStrings(
		&nameConstraintsTemplate.ExcludedURIDomains,
		nameConstraintsExcludedURI.Value(), &nameConstraintsValid)

	return &nameConstraintsTemplate, nameConstraintsValid, nil
}

func setNameConstraintsStrings(ncs *[]string, val string, valid *bool) {
	if val != "" {
		*ncs = []string{val}
		*valid = true
	}
}

func setNameConstraintsIPRanges(ncs *[]*net.IPNet, val string, valid *bool) error {
	if val != "" {
		_, IPNet, err := net.ParseCIDR(val)
		if err != nil {
			return fmt.Errorf("%s: couldn't parse IP CIDR: %w", err, ErrEditBlob)
		}

		*ncs = []*net.IPNet{IPNet}
		*valid = true
	}

	return nil
}

func cleanCertsCryptoAPI() {
	store, err := cryptoAPINameToStore(cryptoAPIFlagPhysicalStoreName.Value())
	if err != nil {
		log.Errorf("error: %s", err.Error())

		return
	}

	registryBase := store.Base
	storeKey := store.Key()

	// Open up the cert store.
	certStoreKey, err := registry.OpenKey(registryBase, storeKey, registry.ALL_ACCESS)
	if err != nil {
		log.Errorf("Couldn't open cert store: %s", err)

		return
	}
	defer certStoreKey.Close()

	// get all subkey names in the cert store
	subKeys, err := certStoreKey.ReadSubKeyNames(0)
	if err != nil {
		log.Errorf("Couldn't list certs in cert store: %s", err)

		return
	}

	// for all certs in the cert store
	for _, subKeyName := range subKeys {
		// Check if the cert is expired
		expired, err := checkCertExpiredCryptoAPI(certStoreKey, subKeyName)
		if err != nil {
			log.Errorf("Couldn't check if cert is expired: %s", err)

			return
		}

		// delete the cert if it's expired
		if expired {
			if err := registry.DeleteKey(certStoreKey, subKeyName); err != nil {
				log.Errorf("Coudn't delete expired cert: %s", err)
			}
		}
	}
}

// This function is specific to the dehydrated certificate method of positive
// overrides, which is deprecated; thus we're not going to maintain this
// function.
//
//nolint:all
func checkCertExpiredCryptoAPI(certStoreKey registry.Key, subKeyName string) (bool, error) {
	// Open the cert
	certKey, err := registry.OpenKey(certStoreKey, subKeyName, registry.ALL_ACCESS)
	if err != nil {
		return false, fmt.Errorf("Couldn't open cert registry key: %s", err)
	}
	defer certKey.Close()

	if expirableMagicName.Value() == "" {
		// Magic expiration is disabled.  Therefore don't consider it expired.
		return false, nil
	}

	// Check for magic value
	isNamecoin, _, err := certKey.GetIntegerValue(expirableMagicName.Value())
	if err != nil {
		// Magic value wasn't found.  Therefore don't consider it expired.
		return false, nil
	}

	if isNamecoin != uint64(expirableMagicData.Value()) {
		// Magic value was found but it wasn't the one we recognize.  Therefore don't consider it expired.
		return false, nil
	}

	// Get metadata about the cert key
	certKeyInfo, err := certKey.Stat()
	if err != nil {
		return false, fmt.Errorf("Couldn't read metadata for cert registry key: %s", err)
	}

	// Get the last modified time
	certKeyModTime := certKeyInfo.ModTime()

	// If the cert's last modified timestamp differs too much from the
	// current time in either direction, consider it expired
	expired := math.Abs(time.Since(certKeyModTime).Seconds()) > float64(certExpirePeriod.Value())

	return expired, nil
}

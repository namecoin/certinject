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
)

const cryptoAPIMagicName = "Namecoin"
const cryptoAPIMagicValue = 1

var ErrInjectCerts = errors.New("error injecting certs")
var ErrEnumerateCerts = fmt.Errorf("error enumerating certs: %w", ErrInjectCerts)
var ErrInvalidPhysicalStore = fmt.Errorf("invalid choice for physical store "+
	"(consider current-user, system, enterprise, group-policy): %w",
	ErrEnumerateCerts)
var ErrGetInitialBlob = fmt.Errorf("error getting initial blob: %w", ErrInjectCerts)
var ErrEditBlob = fmt.Errorf("error editing blob: %w", ErrInjectCerts)

var (
	// cryptoAPIStores consists of every implemented store.
	// when adding a new one, the `%s` variable is optional.
	// if `%s` exists in the Logical string, it is replaced with the value of -store flag
	cryptoAPIStores = map[string]Store{
		"current-user": {registry.CURRENT_USER, `SOFTWARE\Microsoft\SystemCertificates`, `%s\Certificates`},
		"system":       {registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\SystemCertificates`, `%s\Certificates`},
		"enterprise":   {registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EnterpriseCertificates`, `%s\Certificates`},
		"group-policy": {registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\SystemCertificates`, `%s\Certificates`},
	}
)

// Store is used to generate a registry key to open a certificate store in the Windows Registry.
type Store struct {
	Base     registry.Key
	Physical string
	Logical  string // may contain a %s, in which it would be replaced by the -store flag
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

	fingerprintHexUpperList := []string{}

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
	registryBase registry.Key, storeKey string) {
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

	// Add a magic value which indicates that the certificate is a
	// Namecoin cert.  This will be used for deleting expired certs.
	// However, we have to delete it before we create it,
	// so that we make sure that the "last modified" metadata gets updated.
	// If an error occurs during deletion, we ignore it,
	// since it probably just means it wasn't there already.
	_ = certKey.DeleteValue(cryptoAPIMagicName)

	err = certKey.SetDWordValue(cryptoAPIMagicName, cryptoAPIMagicValue)
	if err != nil {
		log.Errorf("Couldn't set magic registry value for certificate: %s", err)
		return
	}

	// Create the registry value which holds the certificate.
	err = certKey.SetBinaryValue("Blob", blobBytes)
	if err != nil {
		log.Errorf("Couldn't set blob registry value for certificate: %s", err)
		return
	}
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

	if len(ekus) > 0 {
		ekuTemplate := x509.Certificate{
			ExtKeyUsage: ekus,
		}

		ekuProperty, err := certblob.BuildExtKeyUsage(&ekuTemplate)
		if err != nil {
			return fmt.Errorf("%s: couldn't marshal extended key usage property: %w", err, ErrEditBlob)
		}

		blob.SetProperty(ekuProperty)
	}

	return nil
}

func buildEKUList() []x509.ExtKeyUsage {
	ekus := []x509.ExtKeyUsage{}

	if ekuAny.Value() {
		ekus = append(ekus, x509.ExtKeyUsageAny)
	}

	if ekuServer.Value() {
		ekus = append(ekus, x509.ExtKeyUsageServerAuth)
	}

	if ekuClient.Value() {
		ekus = append(ekus, x509.ExtKeyUsageClientAuth)
	}

	if ekuCode.Value() {
		ekus = append(ekus, x509.ExtKeyUsageCodeSigning)
	}

	if ekuEmail.Value() {
		ekus = append(ekus, x509.ExtKeyUsageEmailProtection)
	}

	if ekuIPSECEndSystem.Value() {
		ekus = append(ekus, x509.ExtKeyUsageIPSECEndSystem)
	}

	if ekuIPSECTunnel.Value() {
		ekus = append(ekus, x509.ExtKeyUsageIPSECTunnel)
	}

	if ekuIPSECUser.Value() {
		ekus = append(ekus, x509.ExtKeyUsageIPSECUser)
	}

	if ekuTime.Value() {
		ekus = append(ekus, x509.ExtKeyUsageTimeStamping)
	}

	if ekuOCSP.Value() {
		ekus = append(ekus, x509.ExtKeyUsageOCSPSigning)
	}

	if ekuMSCodeCom.Value() {
		ekus = append(ekus, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
	}

	if ekuMSCodeKernel.Value() {
		ekus = append(ekus, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
	}

	return ekus
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

	if nameConstraintsPermittedDNS.Value() != "" {
		nameConstraintsTemplate.PermittedDNSDomains = []string{nameConstraintsPermittedDNS.Value()}
		nameConstraintsValid = true
	}

	if nameConstraintsExcludedDNS.Value() != "" {
		nameConstraintsTemplate.ExcludedDNSDomains = []string{nameConstraintsExcludedDNS.Value()}
		nameConstraintsValid = true
	}

	if nameConstraintsPermittedIP.Value() != "" {
		_, nameConstraintsPermittedIPNet, err := net.ParseCIDR(nameConstraintsPermittedIP.Value())
		if err != nil {
			return nil, false, fmt.Errorf("%s: couldn't parse permitted IP CIDR: %w", err, ErrEditBlob)
		}

		nameConstraintsTemplate.PermittedIPRanges = []*net.IPNet{nameConstraintsPermittedIPNet}
		nameConstraintsValid = true
	}

	if nameConstraintsExcludedIP.Value() != "" {
		_, nameConstraintsExcludedIPNet, err := net.ParseCIDR(nameConstraintsExcludedIP.Value())
		if err != nil {
			return nil, false, fmt.Errorf("%s: couldn't parse excluded IP CIDR: %w", err, ErrEditBlob)
		}

		nameConstraintsTemplate.ExcludedIPRanges = []*net.IPNet{nameConstraintsExcludedIPNet}
		nameConstraintsValid = true
	}

	if nameConstraintsPermittedEmail.Value() != "" {
		nameConstraintsTemplate.PermittedEmailAddresses = []string{nameConstraintsPermittedEmail.Value()}
		nameConstraintsValid = true
	}

	if nameConstraintsExcludedEmail.Value() != "" {
		nameConstraintsTemplate.ExcludedEmailAddresses = []string{nameConstraintsExcludedEmail.Value()}
		nameConstraintsValid = true
	}

	if nameConstraintsPermittedURI.Value() != "" {
		nameConstraintsTemplate.PermittedURIDomains = []string{nameConstraintsPermittedURI.Value()}
		nameConstraintsValid = true
	}

	if nameConstraintsExcludedURI.Value() != "" {
		nameConstraintsTemplate.ExcludedURIDomains = []string{nameConstraintsExcludedURI.Value()}
		nameConstraintsValid = true
	}

	return &nameConstraintsTemplate, nameConstraintsValid, nil
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
//nolint
func checkCertExpiredCryptoAPI(certStoreKey registry.Key, subKeyName string) (bool, error) {
	// Open the cert
	certKey, err := registry.OpenKey(certStoreKey, subKeyName, registry.ALL_ACCESS)
	if err != nil {
		return false, fmt.Errorf("Couldn't open cert registry key: %s", err)
	}
	defer certKey.Close()

	// Check for magic value
	isNamecoin, _, err := certKey.GetIntegerValue(cryptoAPIMagicName)
	if err != nil {
		// Magic value wasn't found.  Therefore don't consider it expired.
		return false, nil
	}

	if isNamecoin != cryptoAPIMagicValue {
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

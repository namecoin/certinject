package x509ext

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
)

var ErrExtensionMarshal = errors.New("error marshaling X.509 extension")

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func buildExtension(template *x509.Certificate, oid []int) ([]byte, error) {
	// Fill in dummy values to the template so that CreateCertificate doesn't
	// complain.
	template.SerialNumber = big.NewInt(1)
	template.Subject = pkix.Name{
		CommonName:   "Dummy from x509ext",
		SerialNumber: "Namecoin TLS Certificate",
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to generate private key: %w", err, ErrExtensionMarshal)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey(priv), priv)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create certificate: %w", err, ErrExtensionMarshal)
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse certificate: %w", err, ErrExtensionMarshal)
	}

	for _, ext := range parsedCert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, nil
		}
	}

	return nil, fmt.Errorf("extension not found: %w", ErrExtensionMarshal)
}

func BuildExtKeyUsage(template *x509.Certificate) ([]byte, error) {
	oidExtensionExtKeyUsage := []int{2, 5, 29, 37}

	return buildExtension(template, oidExtensionExtKeyUsage)
}

func BuildNameConstraints(template *x509.Certificate) ([]byte, error) {
	oidExtensionNameConstraints := []int{2, 5, 29, 30}

	return buildExtension(template, oidExtensionNameConstraints)
}

//go:generate bash generate.sh

package certblob

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/namecoin/certinject/x509ext"
)

//nolint:lll
// Structure defined at:
// https://web.archive.org/web/20200615211614/https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpef/e051aba9-c9df-4f82-a42a-c13012c9d381
type Property struct {
	ID    uint32
	Value []byte
}

// These property ID's are from comments in ReactOS wincrypt.h.
const (
	CertContentCertPropID = 32
	CertContentCRLPropID  = 33
	CertContentCTLPropID  = 34
)

const propReserved = 1

var ErrProperty = errors.New("CryptoAPI blob property")
var ErrPropertyBuild = fmt.Errorf("error building: %w", ErrProperty)
var ErrPropertyMarshal = fmt.Errorf("error marshaling: %w", ErrProperty)
var ErrPropertyInvalidValue = fmt.Errorf("invalid Value: %w", ErrPropertyMarshal)

func (prop *Property) Marshal() ([]byte, error) {
	if prop.Value == nil {
		return nil, fmt.Errorf("nil: %w", ErrPropertyInvalidValue)
	}

	if len(prop.Value) > math.MaxUint32 {
		return nil, fmt.Errorf("overflows uint32 size: %w", ErrPropertyInvalidValue)
	}

	result := make([]byte, 4+4+4)

	// Marshal header
	binary.LittleEndian.PutUint32(result[0:], prop.ID)
	binary.LittleEndian.PutUint32(result[4:], propReserved)
	binary.LittleEndian.PutUint32(result[8:], uint32(len(prop.Value)))

	// Append value
	result = append(result, prop.Value...)

	return result, nil
}

func BuildExtKeyUsage(template *x509.Certificate) (*Property, error) {
	value, err := x509ext.BuildExtKeyUsage(template)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", err, ErrPropertyBuild)
	}

	return &Property{
		ID:    CertEnhkeyUsagePropID,
		Value: value,
	}, nil
}

func BuildNameConstraints(template *x509.Certificate) (*Property, error) {
	value, err := x509ext.BuildNameConstraints(template)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", err, ErrPropertyBuild)
	}

	return &Property{
		ID:    CertRootProgramNameConstraintsPropID,
		Value: value,
	}, nil
}

type Blob map[uint32][]byte

func (b Blob) SetProperty(prop *Property) {
	b[prop.ID] = prop.Value
}

// We sort the ID's so that we get a deterministic Marshaling.
func (b Blob) sortedIDs() []uint32 {
	propIDs := make([]uint32, 0, len(b))
	for id := range b {
		propIDs = append(propIDs, id)
	}

	sort.Slice(propIDs, func(i, j int) bool { return propIDs[i] < propIDs[j] })

	return propIDs
}

func (b Blob) Marshal() ([]byte, error) {
	propIDs := b.sortedIDs()

	result := make([]byte, 0)

	var (
		singleProperty       Property
		resultSingleProperty []byte
		err                  error
	)

	// Iterate through the sorted ID's
	for _, id := range propIDs {
		// Construct a Property
		singleProperty = Property{ID: id, Value: b[id]}

		// Marshal the Property
		resultSingleProperty, err = singleProperty.Marshal()
		if err != nil {
			return nil, fmt.Errorf("ID %d: %w", id, err)
		}

		// Append the Property's bytes to the result
		result = append(result, resultSingleProperty...)
	}

	return result, nil
}

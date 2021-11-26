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

// Structure defined at (archived on Archive.org and Archive.today):
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpef/e051aba9-c9df-4f82-a42a-c13012c9d381
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

var (
	ErrProperty             = errors.New("CryptoAPI blob property")
	ErrPropertyBuild        = fmt.Errorf("error building: %w", ErrProperty)
	ErrPropertyMarshal      = fmt.Errorf("error marshaling: %w", ErrProperty)
	ErrPropertyParse        = fmt.Errorf("error parsing: %w", ErrProperty)
	ErrPropertyInvalidValue = fmt.Errorf("invalid Value: %w", ErrPropertyMarshal)
)

func (prop *Property) Marshal() ([]byte, error) {
	if prop.Value == nil {
		return nil, fmt.Errorf("nil: %w", ErrPropertyInvalidValue)
	}

	if uint64(len(prop.Value)) > math.MaxUint32 {
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

func isContentPropID(propID uint32) bool {
	switch propID {
	case CertContentCertPropID:
		return true
	case CertContentCRLPropID:
		return true
	case CertContentCTLPropID:
		return true
	}

	return false
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

	sort.Slice(propIDs, func(idx1, idx2 int) bool {
		// Content properties MUST be at the end, as per the following spec
		// (archived on Archive.org and Archive.today):
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpef/6a9e35fa-2ac7-4c10-81e1-eabe8d2472f1
		// Any properties that are after the content property will be silently
		// ignored by CryptoAPI!
		isContent1 := isContentPropID(propIDs[idx1])
		isContent2 := isContentPropID(propIDs[idx2])
		if isContent1 != isContent2 {
			return isContent2
		}

		return propIDs[idx1] < propIDs[idx2]
	})

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
	for _, pid := range propIDs {
		// Construct a Property
		singleProperty = Property{ID: pid, Value: b[pid]}

		// Marshal the Property
		resultSingleProperty, err = singleProperty.Marshal()
		if err != nil {
			return nil, fmt.Errorf("ID %d: %w", pid, err)
		}

		// Append the Property's bytes to the result
		result = append(result, resultSingleProperty...)
	}

	return result, nil
}

func ParseBlob(data []byte) (Blob, error) {
	result := Blob{}

	var (
		prop    Property
		propLen int
	)

	for len(data) > 0 {
		if len(data) < 12 {
			return nil, fmt.Errorf("length inconsistent: %w", ErrPropertyParse)
		}

		prop = Property{}

		// PropID is the first 4 bytes
		prop.ID = binary.LittleEndian.Uint32(data[0:])

		// Reserved value is the next 4 bytes
		if binary.LittleEndian.Uint32(data[4:]) != propReserved {
			return nil, fmt.Errorf("unexpected reserved field: %w", ErrPropertyParse)
		}

		// Then the value size
		propLen = int(binary.LittleEndian.Uint32(data[8:]))
		data = data[12:]

		// And finally the value itself
		prop.Value = data[:propLen]
		data = data[propLen:]

		result.SetProperty(&prop)
	}

	return result, nil
}

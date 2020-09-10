package certblob

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

//nolint:lll
// Structure defined at:
// https://web.archive.org/web/20200615211614/https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpef/e051aba9-c9df-4f82-a42a-c13012c9d381
type Property struct {
	ID    uint32
	Value []byte
}

const propReserved = 1

var ErrPropertyMarshal = errors.New("error marshaling CryptoAPI blob property")
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

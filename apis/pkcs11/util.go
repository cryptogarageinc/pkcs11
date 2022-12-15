package pkcs11

import (
	"math"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const hardenedNum = 0x80000000

func ConvertBip32PathFromString(pathStr string) (path []uint32, err error) {
	pathStr = strings.TrimSpace(strings.ToLower(pathStr))
	if strings.HasPrefix(pathStr, "m/") {
		pathStr = pathStr[2:]
	}
	split := strings.Split(pathStr, "/")
	path = make([]uint32, len(split))
	for i, index := range split {
		if index == "" {
			return nil, errors.Errorf("bip32 empty value. val=%s, depth=%d", index, i)
		}
		orgIndex := index
		var x, x1 uint64
		if index[len(index)-1] == '\'' || index[len(index)-1] == 'h' {
			x = hardenedNum
			index = index[:len(index)-1]
		}
		baseNum := 10
		if strings.HasPrefix(index, "0x") {
			baseNum = 16
			index = index[2:]
		}
		x1, err = strconv.ParseUint(index, baseNum, 32)
		if err != nil {
			return nil, err
		} else if x1 > math.MaxInt32 {
			return nil, errors.Errorf("bip32 range over. val=%s, depth=%d", orgIndex, i)
		}
		path[i] = uint32(x | x1)
	}
	return path, nil
}

// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertBip32PathFromString(t *testing.T) {
	path, err := ConvertBip32PathFromString("2")
	assert.NoError(t, err)
	assert.Equal(t, len(path), 1)
	assert.Equal(t, path[0], uint32(2))

	path, err = ConvertBip32PathFromString("0x00002222h")
	assert.NoError(t, err)
	assert.Equal(t, len(path), 1)
	assert.Equal(t, path[0], uint32(0x80002222))

	path, err = ConvertBip32PathFromString("m/44'/0'/0'")
	assert.NoError(t, err)
	assert.Equal(t, len(path), 3)
	assert.Equal(t, path[0], uint32(2147483692))
	assert.Equal(t, path[1], uint32(0x80000000))
	assert.Equal(t, path[2], uint32(0x80000000))

	path, err = ConvertBip32PathFromString("m/44h/0h/1h/0/10")
	assert.NoError(t, err)
	assert.Equal(t, len(path), 5)
	assert.Equal(t, path[0], uint32(2147483692))
	assert.Equal(t, path[1], uint32(0x80000000))
	assert.Equal(t, path[2], uint32(0x80000001))
	assert.Equal(t, path[3], uint32(0))
	assert.Equal(t, path[4], uint32(10))

	path, err = ConvertBip32PathFromString("m/0/0x80000000/1")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "bip32 range over. val=0x80000000, depth=1")

	path, err = ConvertBip32PathFromString("m///")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "bip32 empty value. val=, depth=0")

	path, err = ConvertBip32PathFromString("-1")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "strconv.ParseUint: parsing \"-1\": invalid syntax")

	path, err = ConvertBip32PathFromString("abcdefgh")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "strconv.ParseUint: parsing \"abcdefg\": invalid syntax")

}

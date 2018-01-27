package utils

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/rand"
)

func bytesToInt64(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}

// new a insecure rand creator from random seed
func newInsecureRand() *rand.Rand {
	randomHash := GetRandHash()[:]
	source := rand.NewSource(bytesToInt64(randomHash))
	return rand.New(source)
}

// GetRandHash create a random Hash(utils.Hash)
func GetRandHash() *Hash {
	seed := make([]byte, 32)
	rand.Read(seed)
	tmpStr := hex.EncodeToString(seed)
	return HashFromString(tmpStr)
}

// InsecureRandRange create a random number in [0, limit)
func InsecureRandRange(limit int64) uint64 {
	if limit == 0 {
		return 0
	}
	r := newInsecureRand()
	return uint64(abs(r.Int63n(limit)).(int64))
}

// InsecureRand32 create a random number in [0 math.MaxUint32)
func InsecureRand32() uint32 {
	r := newInsecureRand()
	return uint32(abs(r.Int31n(math.MaxInt32)).(int32)) + uint32(abs(r.Int31n(math.MaxInt32)).(int32))
}

// InsecureRandBits create a random number following  specified bit count
func InsecureRandBits(bit uint8) uint64 {
	r := newInsecureRand()
	maxNum := int64(((1<<(bit-1))-1)*2 + 1)
	return uint64(abs(r.Int63n(maxNum)).(int64))
}

// InsecureRandBool create true or false randomly
func InsecureRandBool() bool {
	r := newInsecureRand()
	tmpInt := r.Intn(2)
	return tmpInt == 1
}

func abs(i interface{}) interface{} {
	switch i.(type) {
	case int64:
		tmp := i.(int64)
		if tmp < 0 {
			return -tmp
		}
		return tmp
	case int32:
		tmp := i.(int32)
		if tmp < 0 {
			return -tmp
		}
		return tmp
	}
	return nil
}

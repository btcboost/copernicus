package utils

import (
	"fmt"
	"math"
	"testing"
)

func TestRandom(t *testing.T) {
	trueCount := 0
	falseCount := 0

	for i := 0; i < 1000; i++ {
		NumUint64 := InsecureRandRange(1000000)
		if NumUint64 > 1000000 {
			t.Error("InsecureRandRange() create a random number bigger than 10000")
		}

		NumUint32 := InsecureRand32()
		if NumUint32 > math.MaxUint32 {
			t.Error("InsecureRand32() creates a random number bigger than math.MaxUint32")
		}
		fmt.Println(NumUint32)

		NumFromRandBit := InsecureRandBits(6)
		if NumFromRandBit > (((1<<(6-1))-1)*2 + 1) {
			t.Error("InsecureRandBits() creates a random numner bigger than bit-specific MaxNumber")
		}

		BoolFromRandFunc := InsecureRandBool()
		if BoolFromRandFunc {
			trueCount++
		} else {
			falseCount++
		}
	}

	if trueCount == 0 || falseCount == 0 {
		t.Error("InsecureRandBool() maybe needed to check")
	}
}

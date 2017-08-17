package model

import (
	"testing"
)

func TestScript(t *testing.T) {
	//1. test borrow lenth from ScriptFreeList
	var myscriptlist ScriptFreeList
	bufOne := myscriptlist.Borrow(freeListMaxScriptSize + 10)
	t.Log("lenth for Slice with param greater than freeListMaxScriptSize : ", len(bufOne))

	bufTwo := myscriptlist.Borrow(freeListMaxScriptSize - 10)
	t.Log("lenth for Slice with param less than freeListMaxScriptSize : ", len(bufTwo))

	bufThree := myscriptlist.Borrow(freeListMaxScriptSize)
	t.Log("lenth for Slice with param equal freeListMaxScriptSize : ", len(bufThree))

	//2. return The BufOne slice to scriptlist
	copy(bufOne, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	myscriptlist.Return(bufOne)

	//3. again borrow the slice from ScriptFreeList will not equal bufOne
	bufFour := myscriptlist.Borrow(freeListMaxScriptSize)
	t.Log("again borrow slice lenth : ", len(bufFour), " : content : ", bufFour)

	//4. return The bufThree slice to scriptlist
	copy(bufThree, "bbbbbbbbbbbbbbbbbbbbb")
	myscriptlist.Return(bufThree)

	//5. with get The slice from list
	bufFour = myscriptlist.Borrow(freeListMaxScriptSize)
	t.Log("get The slice lenth : ", len(bufFour), " : content : ", bufFour)

}

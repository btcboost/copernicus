package model

import (
	"io"
	"os"
	"testing"

	"github.com/btcboost/copernicus/utils"
)

func TestNewOutPoint(t *testing.T) {
	var buf utils.Hash
	for i := 0; i < utils.HashSize; i++ {
		buf[i] = byte(i + 49)
	}

	//1. create object
	s := NewOutPoint(&buf, 10)
	t.Log("index : ", s.Index, " : ", s.Hash)

	//2. object byte to string
	t.Log("String() : ", s.String())

	//3. create file
	file, err := os.OpenFile("txOut.txt", os.O_RDWR|os.O_CREATE, 0666)
	checkErr(err)

	defer file.Close()

	//4. write news In file
	err = s.WriteOutPoint(file, 10, 1)
	checkErr(err)

	//5. seek file IO
	txOutRead := &OutPoint{Hash: &buf}
	_, err = file.Seek(0, io.SeekStart)
	checkErr(err)

	//6. read news from file IO
	err = txOutRead.ReadOutPoint(file, 1)
	checkErr(err)

	t.Log(txOutRead)

}

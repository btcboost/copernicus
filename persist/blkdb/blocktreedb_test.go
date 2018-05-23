package blkdb

import (
	"testing"
	
	"github.com/btcboost/copernicus/persist/db"
)


func TestMain(m *testing.M){
	config := BlockTreeDBConfig{do: &db.DBOption{CacheSize: 100}}
	InitBlockTreDB(&config)
	m.Run()
}
func TestNewCoinsLruCache(t *testing.T) {
	
	blockTreeDb.LoadBlockIndexGuts()
}




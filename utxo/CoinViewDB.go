package utxo

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/btcboost/copernicus/conf"
	"github.com/btcboost/copernicus/model"
	"github.com/btcboost/copernicus/orm"
	"github.com/btcboost/copernicus/orm/database"
	"github.com/btcboost/copernicus/utils"
)

const bucketKey = "chainstate"

type CoinViewDB struct {
	database.DBBase
	bucket database.Bucket
}

func (coinViewDB *CoinViewDB) GetCoin(outpoint *model.OutPoint, coin *Coin) bool {
	coinEntry := NewCoinEntry(outpoint)
	var v []byte
	err := coinViewDB.DBBase.View([]byte(bucketKey), func(bucket database.Bucket) error {
		v = bucket.Get(coinEntry.GetSerKey())
		return nil
	})
	buf := bytes.NewBuffer(v)
	tmp, err := DeserializeCoin(buf)
	if err != nil {
		return false
	}
	coin.HeightAndIsCoinBase = tmp.HeightAndIsCoinBase
	coin.TxOut = tmp.TxOut
	return true
}

func (coinViewDB *CoinViewDB) HaveCoin(outpoint *model.OutPoint) bool {
	coinEntry := NewCoinEntry(outpoint)
	var v bool
	err := coinViewDB.DBBase.View([]byte(bucketKey), func(bucket database.Bucket) error {
		v = bucket.Exists(coinEntry.GetSerKey())
		return nil
	})
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	return v

}

func (coinViewDB *CoinViewDB) SetBestBlock(hash *utils.Hash) {
	err := coinViewDB.DBBase.Update([]byte(bucketKey), func(bucket database.Bucket) error {
		err := bucket.Put([]byte{orm.DB_BEST_BLOCK}, hash.GetCloneBytes())
		return err
	})
	if err != nil {
		fmt.Println(err.Error())
	}
}

func (coinViewDB *CoinViewDB) GetBestBlock() utils.Hash {
	var v []byte
	hash := utils.Hash{}
	err := coinViewDB.DBBase.View([]byte(bucketKey), func(bucket database.Bucket) error {
		v = bucket.Get([]byte{orm.DB_BEST_BLOCK})
		return nil
	})
	if err != nil || v == nil {
		return hash
	}
	hash.SetBytes(v)
	return hash
}

func (coinViewDB *CoinViewDB) BatchWrite(mapCoins CacheCoins, hash *utils.Hash) (bool, error) {
	count := 0
	changed := 0
	for k, v := range mapCoins {
		if v.Flags&COIN_ENTRY_DIRTY == COIN_ENTRY_DIRTY {
			coinEntry := NewCoinEntry(&k)
			if v.Coin.IsSpent() {
				err := coinViewDB.DBBase.Update([]byte(bucketKey), func(bucket database.Bucket) error {
					err := bucket.Delete(coinEntry.GetSerKey())
					return err
				})
				if err != nil {
					return false, err
				}
			} else {
				b, err := v.Coin.GetSerialize()
				if err != nil {
					return false, err
				}
				err = coinViewDB.DBBase.Update([]byte(bucketKey), func(bucket database.Bucket) error {
					err := bucket.Put(coinEntry.GetSerKey(), b)
					return err
				})
				if err != nil {
					return false, err
				}
			}
			changed++
		}
		count++
	}
	if !hash.IsNull() {
		err := coinViewDB.DBBase.Update([]byte(bucketKey), func(bucket database.Bucket) error {
			err := bucket.Put([]byte{orm.DB_BEST_BLOCK}, hash.GetCloneBytes())
			return err
		})
		if err != nil {
			return false, err
		}
	}

	mapCoins = make(CacheCoins) // clear
	fmt.Println("coin", "committed %d changed transcation outputs (out of %d) to coin databse", changed, count)
	return true, nil
}

func (coinViewDB *CoinViewDB) EstimateSize() int {
	var size int
	err := coinViewDB.DBBase.View([]byte(bucketKey), func(bucket database.Bucket) error {
		size = bucket.EstimateSize()
		return nil
	})
	if err != nil {
		fmt.Println(err.Error())
		return 0
	}
	return size
}

func (coinViewDB *CoinViewDB) Cursor() *CoinsViewCursor {
	cursor := NewCoinsViewCursor(coinViewDB.bucket.Cursor(), coinViewDB.DBBase, coinViewDB.GetBestBlock())
	cursor.Seek([]byte{orm.DB_COIN})
	if cursor.Valid() {
		entry := NewCoinEntry(cursor.keyTmp.outpoint)
		outpoint := cursor.GetKey()
		if outpoint != nil {
			entry.outpoint = outpoint
			cursor.keyTmp.key = entry.key
		}
	} else {
		cursor.keyTmp.key = 0
	}

	return cursor
}

func NewCoinViewDB() *CoinViewDB {
	coinViewDB := new(CoinViewDB)
	path := conf.AppConf.DataDir + string(filepath.Separator) + "chainstate"
	db, err := orm.InitDB(orm.DBBolt, path)
	if err != nil {
		panic(err)
	}
	b, err := db.CreateIfNotExists([]byte("chainstate"))
	if err != nil {
		panic(err)
	}
	coinViewDB.DBBase = db
	coinViewDB.bucket = b

	return coinViewDB
}

package utxo

import (
	"bytes"

	"github.com/boltdb/bolt"
	"github.com/btcboost/copernicus/model"
	"github.com/btcboost/copernicus/orm"
	"github.com/btcboost/copernicus/orm/database"
	"github.com/btcboost/copernicus/utils"
)

type CoinsViewCursor struct {
	hashBlock utils.Hash
	keyTmp    CoinEntry
	database.DBBase
	bolt.Cursor
}

func NewCoinsViewCursor(cursor *bolt.Cursor, db database.DBBase, hash utils.Hash) *CoinsViewCursor {
	return &CoinsViewCursor{
		hashBlock: hash,
		DBBase:    db,
		Cursor:    *cursor,
	}
}

func (coinsViewCursor *CoinsViewCursor) Valid() bool {
	return coinsViewCursor.keyTmp.key == orm.DB_COIN
}

func (coinsViewCursor *CoinsViewCursor) GetKey() *model.OutPoint {
	if coinsViewCursor.keyTmp.key == orm.DB_COIN {
		return coinsViewCursor.keyTmp.outpoint
	}
	return nil
}

func (coinsViewCursor *CoinsViewCursor) GetValue() *Coin {
	_, v := coinsViewCursor.Seek(coinsViewCursor.keyTmp.GetSerKey())
	buf := bytes.NewBuffer(v)
	coin, err := DeserializeCoin(buf)
	if err != nil {
		return nil
	}
	return coin
}

func (coinsViewCursor *CoinsViewCursor) Next() { // override
	coinsViewCursor.Cursor.Next()
	coinEntry := NewCoinEntry(coinsViewCursor.keyTmp.outpoint)
	if !coinsViewCursor.Valid() || coinsViewCursor.GetKey() == nil {
		coinsViewCursor.keyTmp.key = 0
	} else {
		coinsViewCursor.keyTmp.key = coinEntry.key
	}
}

func (coinsViewCursor *CoinsViewCursor) GetValueSize() int {
	_, v := coinsViewCursor.Seek(coinsViewCursor.keyTmp.GetSerKey())
	return len(v)
}

func (coinsViewCursor *CoinsViewCursor) GetBestBlock() utils.Hash {
	return coinsViewCursor.hashBlock
}

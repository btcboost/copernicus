package boltdb

import (
	"github.com/boltdb/bolt"
	"github.com/btcboost/copernicus/orm/database"
)

type bucket struct {
	database.Bucket
	boltBucket *bolt.Bucket
}

func (bucket *bucket) ForEach(fn func(key, value []byte) error) error {
	c := bucket.boltBucket.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		err := fn(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func (bucket *bucket) Cursor() *bolt.Cursor {
	c := bucket.boltBucket.Cursor()
	return c
}

func (bucket *bucket) Writable() bool {
	return bucket.boltBucket.Writable()
}

func (bucket *bucket) Put(key, value []byte) error {
	err := bucket.boltBucket.Put(key, value)
	return err
}

func (bucket *bucket) Get(key []byte) []byte {
	return bucket.boltBucket.Get(key)

}

func (bucket *bucket) Exists(key []byte) bool {
	v := bucket.boltBucket.Get(key)
	return v != nil

}

func (bucket *bucket) Delete(key []byte) error {
	err := bucket.boltBucket.Delete(key)
	return err
}

func (bucket *bucket) EstimateSize() int {
	return 0
}

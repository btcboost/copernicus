package database

import "github.com/boltdb/bolt"

type Bucket interface {
	ForEach(func(k, v []byte) error) error

	Cursor() *bolt.Cursor

	Writable() bool

	Put(key, value []byte) error

	Get(key []byte) []byte

	Delete(key []byte) error

	Exists(key []byte) bool

	EstimateSize() int
}

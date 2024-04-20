package jwt

import "sync"

// KeyStore is a data structure that stores pairs of KeyId and PublicKey in a concurrent-safe manner.
type KeyStore struct {
	lock sync.RWMutex
	keys map[string]PublicKey
}

// NewKeyStore creates a new KeyStore.
func NewKeyStore() *KeyStore {
	return &KeyStore{
		lock: sync.RWMutex{},
		keys: make(map[string]PublicKey),
	}
}

// AddKey adds a new key to the KeyStore.
func (ks *KeyStore) AddKey(id string, key PublicKey) {
	ks.lock.Lock()
	ks.keys[id] = key
	ks.lock.Unlock()
}

// GetKey retrieves a key from the KeyStore.
func (ks *KeyStore) GetKey(id string) PublicKey {
	ks.lock.RLock()
	ret := ks.keys[id]
	ks.lock.RUnlock()
	return ret
}

// SetMany sets multiple keys in the KeyStore.
func (ks *KeyStore) SetMany(keys map[string]PublicKey) {
	ks.lock.Lock()
	for k, v := range keys {
		ks.keys[k] = v
	}
	ks.lock.Unlock()
}

func (ks *KeyStore) IsEmpty() bool {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	return len(ks.keys) == 0
}

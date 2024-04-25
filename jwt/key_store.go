package jwt

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// KeyStore is a data structure that stores pairs of KeyId and PublicKey in a concurrent-safe manner.
type KeyStore struct {
	lock       sync.RWMutex
	keys       map[string]PublicKey
	filePath   string
	nextUpdate time.Time
	updateLock sync.Mutex
}

// NewKeyStore creates a new KeyStore.
func NewKeyStore(filepath string) *KeyStore {
	return &KeyStore{
		filePath: filepath,
		lock:     sync.RWMutex{},
		keys:     make(map[string]PublicKey),
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
	if len(ret) == 0 {
		ks.TryUpdateKeys()
		ks.lock.RLock()
		ret = ks.keys[id]
		ks.lock.RUnlock()
	}
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

// IsEmpty checks if the KeyStore is empty.
func (ks *KeyStore) IsEmpty() bool {
	ks.lock.RLock()
	defer ks.lock.RUnlock()
	return len(ks.keys) == 0
}

func loadPublicKeysFromFile(filePath string) (map[string]PublicKey, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return DecodePublicKeys(f)
}

// UpdateKeys updates the keys in the KeyStore.
func (ks *KeyStore) UpdateKeys() error {
	var err error
	var keys map[string]PublicKey
	if len(ks.filePath) != 0 {
		keys, err = loadPublicKeysFromFile(ks.filePath)
	} else {
		keys, err = FetchPublicKeys()
	}
	if err != nil {
		return fmt.Errorf("load public keys: %w", err)
	}
	ks.SetMany(keys)
	return nil
}

func (ks *KeyStore) TryUpdateKeys() {
	ks.updateLock.Lock()
	defer ks.updateLock.Unlock()
	if time.Now().Before(ks.nextUpdate) {
		return
	}
	ks.nextUpdate = time.Now().Add(5 * time.Second)
	if err := ks.UpdateKeys(); err != nil {
		log.Printf("Failed to update public key: %+v", err)
	}
}

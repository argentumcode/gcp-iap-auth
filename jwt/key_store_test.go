package jwt

import (
	"bytes"
	"testing"
)

func TestKeyStore(t *testing.T) {
	ks := NewKeyStore()

	if !ks.IsEmpty() {
		t.Errorf("IsEmpty failed, expected true, got false")
	}

	// Test AddKey
	keyID := "key1"
	key := []byte("testkey")
	ks.AddKey("key1", []byte("testkey"))

	if k := ks.GetKey(keyID); string(k) != string(key) {
		t.Errorf("AddKey failed, expected %v, got %v", string(key), string(k))
	}

	// Test SetMany
	ks.SetMany(map[string]PublicKey{
		"key3": []byte("testkey3"),
	})

	if k := ks.GetKey("key3"); !bytes.Equal(k, []byte("testkey3")) {
		t.Errorf("SetMany failed, expected %v, got %v", string("testkey3"), string(k))
	}

	// Test GetKey for not found key
	if k := ks.GetKey("key2"); k != nil {
		t.Errorf("GetKey failed, expected nil, got %v", k)
	}

	if ks.IsEmpty() {
		t.Errorf("IsEmpty failed, expected false, got true")
	}
}

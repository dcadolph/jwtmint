package jwks

import (
	"fmt"
	"sync"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// KeySet is a thread-safe in-memory collection of JWKs indexed by kid.
//
// A KeySet with no kids on its members is still usable, but Lookup will only succeed
// for empty-string keys. For multi-key serving (rotation), every key should have a kid.
type KeySet struct {
	mu   sync.RWMutex
	keys map[string]JWK
}

// NewKeySet returns an empty KeySet.
func NewKeySet() *KeySet {
	return &KeySet{keys: make(map[string]JWK)}
}

// FromJWKS returns a KeySet populated from the given JWKS. Duplicate kids result in an error.
func FromJWKS(j JWKS) (*KeySet, error) {
	ks := NewKeySet()
	for _, k := range j.Keys {
		if err := ks.Add(k); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

// Add inserts the given JWK. Returns an error if a key with the same kid already exists.
func (ks *KeySet) Add(j JWK) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.keys[j.Kid]; exists {
		return fmt.Errorf("%w: jwk with kid %q already in key set", pkgerr.ErrInvalidValue, j.Kid)
	}
	ks.keys[j.Kid] = j
	return nil
}

// Replace inserts or overwrites the given JWK by kid.
func (ks *KeySet) Replace(j JWK) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[j.Kid] = j
}

// Remove deletes the JWK with the given kid. Missing kids are a no-op.
func (ks *KeySet) Remove(kid string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	delete(ks.keys, kid)
}

// Lookup returns the JWK with the given kid, or ErrNotFound.
func (ks *KeySet) Lookup(kid string) (JWK, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	j, ok := ks.keys[kid]
	if !ok {
		return JWK{}, fmt.Errorf("%w: kid %q", pkgerr.ErrNotFound, kid)
	}
	return j, nil
}

// PublicKey returns the Go public key for the JWK with the given kid.
func (ks *KeySet) PublicKey(kid string) (any, error) {
	j, err := ks.Lookup(kid)
	if err != nil {
		return nil, err
	}
	return PublicKeyFromJWK(j)
}

// JWKS returns a snapshot of the key set as an RFC 7517 JWKS.
func (ks *KeySet) JWKS() JWKS {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := JWKS{Keys: make([]JWK, 0, len(ks.keys))}
	for _, j := range ks.keys {
		out.Keys = append(out.Keys, j)
	}
	return out
}

// Len returns the number of JWKs in the set.
func (ks *KeySet) Len() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.keys)
}

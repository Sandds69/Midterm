// Package crypto contains every cryptographic primitive used by Health Metrics Vault.
//
// SECURITY MECHANISMS IN THIS FILE
//   - Password storage: bcrypt (adaptive, salted, slow hash). Plain-text passwords
//     never touch the database, so a DB dump does not reveal credentials.
//   - Data at Rest encryption: AES-256-GCM (authenticated encryption). Medical
//     records are encrypted BEFORE they are written to PostgreSQL. Anyone who steals
//     the database (backup leak, SQL injection elsewhere, rogue DBA) sees only
//     ciphertext. GCM also provides integrity: tampered ciphertext fails to decrypt.
//   - Key management: the AES key is NEVER hardcoded. It is passed in by the caller,
//     which loads it from the AES_ENCRYPTION_KEY environment variable (see config).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the work factor. 12 is a sensible 2020s default: ~250ms per hash,
// which makes offline brute-force of leaked hashes expensive.
const bcryptCost = 12

// MaxPasswordBytes is bcrypt's hard input limit. Longer inputs would be silently
// truncated by some implementations, so we reject them explicitly instead.
const MaxPasswordBytes = 72

var (
	ErrPasswordTooLong     = errors.New("password exceeds 72 bytes")
	ErrInvalidKey          = errors.New("AES key must be 64 hex characters (32 bytes / AES-256)")
	ErrMalformedCiphertext = errors.New("malformed ciphertext")
	ErrDecryptionFailed    = errors.New("decryption failed: wrong key or tampered data")
)

// ---------------------------------------------------------------------------
// Password hashing (bcrypt)
// ---------------------------------------------------------------------------

// HashPassword returns a salted bcrypt hash of the password.
// bcrypt generates a random per-password salt internally, so two users with the
// same password get different hashes (defeats rainbow tables).
func HashPassword(password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPasswordHash compares a candidate password with a stored bcrypt hash.
// bcrypt.CompareHashAndPassword is constant-time with respect to the hash
// comparison, mitigating timing side-channel attacks.
func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ---------------------------------------------------------------------------
// Data at Rest encryption (AES-256-GCM)
// ---------------------------------------------------------------------------

// ValidateKey checks that the key is a valid hex-encoded 256-bit key.
// Called once at startup so the server fails fast on misconfiguration.
func ValidateKey(key string) error {
	_, err := parseKey(key)
	return err
}

// parseKey decodes the hex-encoded key and enforces AES-256 (32 bytes).
// Generate a key with:  openssl rand -hex 32
func parseKey(key string) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimSpace(key))
	if err != nil || len(k) != 32 {
		return nil, ErrInvalidKey
	}
	return k, nil
}

func newGCM(key string) (cipher.AEAD, error) {
	k, err := parseKey(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptAESGCM encrypts plainText with AES-256-GCM.
//
// Output format (base64-encoded):  nonce(12 bytes) || ciphertext || GCM tag(16 bytes)
//
// SECURITY: A fresh random nonce is generated from the OS CSPRNG for EVERY
// encryption. Reusing a nonce with the same key in GCM is catastrophic (it leaks
// the XOR of plaintexts and allows tag forgery), so we never derive or reuse it.
func EncryptAESGCM(plainText string, key string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal appends ciphertext+tag to the nonce slice -> nonce||ct||tag.
	sealed := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptAESGCM reverses EncryptAESGCM.
//
// SECURITY: gcm.Open verifies the authentication tag before returning any
// plaintext. If a single bit of the stored ciphertext was modified (e.g. by an
// attacker with DB write access), decryption fails instead of returning garbage.
func DecryptAESGCM(cipherText string, key string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", ErrMalformedCiphertext
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+gcm.Overhead() {
		return "", ErrMalformedCiphertext
	}

	nonce, sealed := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}
	return string(plain), nil
}

package crypto

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Test-only key. Real keys come from the AES_ENCRYPTION_KEY environment variable.
const testKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const otherKey = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("CorrectHorse!42")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "CorrectHorse!42" {
		t.Fatal("hash must not equal plaintext")
	}
	if !CheckPasswordHash("CorrectHorse!42", hash) {
		t.Fatal("valid password rejected")
	}
	if CheckPasswordHash("wrong", hash) {
		t.Fatal("invalid password accepted")
	}
	if _, err := HashPassword(strings.Repeat("a", 73)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatal("expected ErrPasswordTooLong")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	plain := "Blood type: O+, Allergies: penicillin"
	ct, err := EncryptAESGCM(plain, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ct, "penicillin") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := DecryptAESGCM(ct, testKey)
	if err != nil || got != plain {
		t.Fatalf("round trip failed: %v %q", err, got)
	}
}

func TestAESGCMNonceIsRandom(t *testing.T) {
	a, _ := EncryptAESGCM("same", testKey)
	b, _ := EncryptAESGCM("same", testKey)
	if a == b {
		t.Fatal("identical ciphertexts: nonce reuse")
	}
}

func TestAESGCMWrongKey(t *testing.T) {
	ct, _ := EncryptAESGCM("secret", testKey)
	if _, err := DecryptAESGCM(ct, otherKey); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestAESGCMTamperDetection(t *testing.T) {
	ct, _ := EncryptAESGCM("secret", testKey)
	raw, _ := base64.StdEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 0x01 // flip one bit in the tag
	if _, err := DecryptAESGCM(base64.StdEncoding.EncodeToString(raw), testKey); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampering not detected: %v", err)
	}
}

func TestInvalidKeys(t *testing.T) {
	for _, k := range []string{"", "short", "zz" + testKey[2:], testKey[:62]} {
		if err := ValidateKey(k); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("key %q should be invalid", k)
		}
	}
}

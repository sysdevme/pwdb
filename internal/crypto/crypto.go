package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Service struct {
	master string
}

func NewService(masterPassword string) *Service {
	return &Service{master: masterPassword}
}

func (s *Service) CheckMaster(candidate string) bool {
	return s.master != "" && candidate == s.master
}

func (s *Service) deriveKey(salt []byte) []byte {
	return argon2.IDKey([]byte(s.master), salt, 2, 128*1024, 4, 32)
}

func (s *Service) Encrypt(plaintext string) ([]byte, error) {
	if s.master == "" {
		return nil, errors.New("master password not set")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := s.deriveKey(salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	blob := append(salt, nonce...)
	blob = append(blob, ciphertext...)
	return blob, nil
}

func (s *Service) Decrypt(blob []byte) (string, error) {
	if s.master == "" {
		return "", errors.New("master password not set")
	}
	if len(blob) < 16 {
		return "", errors.New("invalid blob")
	}
	salt := blob[:16]
	key := s.deriveKey(salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < 16+nonceSize {
		return "", errors.New("invalid blob")
	}
	nonce := blob[16 : 16+nonceSize]
	ciphertext := blob[16+nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// HashForDisplay is used only for UI fingerprinting, never for auth.
func HashForDisplay(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password required")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 128*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + ":" + base64.RawStdEncoding.EncodeToString(hash), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	check := argon2.IDKey([]byte(password), salt, 2, 128*1024, 4, 32)
	return subtleCompare(hash, check)
}

func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var res byte
	for i := 0; i < len(a); i++ {
		res |= a[i] ^ b[i]
	}
	return res == 0
}

func GenerateRandomKey(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("invalid key size")
	}
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func KeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func derivePasswordKey(password string, salt []byte) ([]byte, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password required")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt required")
	}
	return argon2.IDKey([]byte(password), salt, 2, 128*1024, 4, 32), nil
}

func EncryptWithKey(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func DecryptWithKey(key []byte, blob []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, errors.New("invalid blob")
	}
	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func WrapKeyWithPassword(password string, key []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	derived, err := derivePasswordKey(password, salt)
	if err != nil {
		return nil, err
	}
	wrapped, err := EncryptWithKey(derived, key)
	if err != nil {
		return nil, err
	}
	return append(salt, wrapped...), nil
}

func UnwrapKeyWithPassword(password string, blob []byte) ([]byte, error) {
	if len(blob) < 16 {
		return nil, errors.New("invalid wrapped key")
	}
	salt := blob[:16]
	derived, err := derivePasswordKey(password, salt)
	if err != nil {
		return nil, err
	}
	return DecryptWithKey(derived, blob[16:])
}

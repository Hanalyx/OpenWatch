package utils

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// generateRandomString generates a secure random string of specified length
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a less secure method if crypto/rand fails
		// This should rarely happen
		panic("failed to generate random string")
	}
	
	// Convert to base64 and remove special characters
	str := base64.URLEncoding.EncodeToString(bytes)
	str = strings.ReplaceAll(str, "-", "")
	str = strings.ReplaceAll(str, "_", "")
	str = strings.ReplaceAll(str, "=", "")
	
	// Ensure we have the requested length
	if len(str) < length {
		return generateRandomString(length)
	}
	
	return str[:length]
}
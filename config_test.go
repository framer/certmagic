// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/certmagic/internal/testutil"
	"github.com/mholt/acmez/v3/acme"
)

func TestSaveCertResource(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\t"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\n"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte(" "), []byte(""))
	if !reflect.DeepEqual(cert, siteData) {
		t.Errorf("Expected '%+v' to match '%+v'\n%s\n%s", cert.IssuerData, siteData.IssuerData, string(cert.IssuerData), string(siteData.IssuerData))
	}
}

type mockStorageWithLease struct {
	*FileStorage
	renewCalled  bool
	renewError   error
	lastLockKey  string
	lastDuration time.Duration
}

func (m *mockStorageWithLease) RenewLockLease(ctx context.Context, lockKey string, leaseDuration time.Duration) error {
	m.renewCalled = true
	m.lastLockKey = lockKey
	m.lastDuration = leaseDuration
	return m.renewError
}

func TestRenewLockLeaseDuration(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	mockStorage := &mockStorageWithLease{
		FileStorage: &FileStorage{Path: tmpDir},
	}

	// Test attempt 0
	cfg := &Config{Logger: defaultTestLogger}
	cfg.renewLockLease(ctx, mockStorage, "test-lock", 0)
	expected := retryIntervals[0] + DefaultACME.CertObtainTimeout
	testutil.RequireEqual(t, expected, mockStorage.lastDuration)

	// Test attempt beyond array bounds
	cfg.renewLockLease(ctx, mockStorage, "test-lock", 999)
	expected = maxRetryDuration + DefaultACME.CertObtainTimeout
	testutil.RequireEqual(t, expected, mockStorage.lastDuration)
}

// Test that lease renewal works when storage supports it
func TestRenewLockLeaseWithInterface(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	mockStorage := &mockStorageWithLease{
		FileStorage: &FileStorage{Path: tmpDir},
	}

	cfg := &Config{Logger: defaultTestLogger}
	err = cfg.renewLockLease(ctx, mockStorage, "test-lock", 0)
	testutil.RequireNoError(t, err)

	testutil.RequireEqual(t, true, mockStorage.renewCalled)
}

// Test that no error occurs when storage doesn't support lease renewal
func TestRenewLockLeaseWithoutInterface(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	storage := &FileStorage{Path: tmpDir}

	cfg := &Config{Logger: defaultTestLogger}
	err = cfg.renewLockLease(ctx, storage, "test-lock", 0)
	testutil.RequireNoError(t, err)
}

func mustJSON(val any) []byte {
	result, err := json.Marshal(val)
	if err != nil {
		panic("marshaling JSON: " + err.Error())
	}
	return result
}

// Test certificate and key for bundle mode tests
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIBgDCCASegAwIBAgIUZ8ef3RJ8VIYFnqsK11i74ms+T+8wCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjUxMjAyMTE1NjE4WhcNMjYxMjAy
MTE1NjE4WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABEG5s2FbSkBKBImV4mv5k6iXX7bC23oVC/8pxuPCMCV/CpWpBbnB
CagGQ/xjeMsfdFLVMmYWhvvUtvwLC7dCr0mjUzBRMB0GA1UdDgQWBBSIa6X5luCf
7PXFyTJI1j7hNZD1wzAfBgNVHSMEGDAWgBSIa6X5luCf7PXFyTJI1j7hNZD1wzAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFFrJ+/KgnOAFr+/mgW0
Aha54okhtZ2xfc/BmoxBrQ10AiAH/nAINmhmDbj+l5Q8g9wFbWz4tLHJmJwKVQBG
zywvYA==
-----END CERTIFICATE-----`

const testKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL+JOk55ogoK9AyCEep1ao1Rhbb1RCFma0kMzu3znvJ6oAoGCCqGSM49
AwEHoUQDQgAEQbmzYVtKQEoEiZXia/mTqJdftsLbehUL/ynG48IwJX8KlakFucEJ
qAZD/GN4yx90UtUyZhaG+9S2/AsLt0KvSQ==
-----END EC PRIVATE KEY-----`

func TestStorageModeLegacy(t *testing.T) {
	ctx := context.Background()

	// Set legacy storage mode
	originalEnv := os.Getenv(StorageModeEnv)
	defer os.Setenv(StorageModeEnv, originalEnv)
	os.Setenv(StorageModeEnv, StorageModeLegacy)

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp_legacy"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify legacy files exist (.key, .crt, .json)
	issuerKey := am.IssuerKey()
	keyPath := StorageKeys.SitePrivateKey(issuerKey, domain)
	certPath := StorageKeys.SiteCert(issuerKey, domain)
	metaPath := StorageKeys.SiteMeta(issuerKey, domain)

	if !testConfig.Storage.Exists(ctx, keyPath) {
		t.Errorf("Expected private key file to exist at %s", keyPath)
	}
	if !testConfig.Storage.Exists(ctx, certPath) {
		t.Errorf("Expected certificate file to exist at %s", certPath)
	}
	if !testConfig.Storage.Exists(ctx, metaPath) {
		t.Errorf("Expected metadata file to exist at %s", metaPath)
	}

	// Verify bundle file does NOT exist
	bundlePath := StorageKeys.CertificateResource(issuerKey, domain)
	if testConfig.Storage.Exists(ctx, bundlePath) {
		t.Errorf("Expected bundle file NOT to exist at %s in legacy mode", bundlePath)
	}

	// Verify we can load it back
	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	if string(siteData.PrivateKeyPEM) != keyContents {
		t.Errorf("Expected private key %q, got %q", keyContents, string(siteData.PrivateKeyPEM))
	}
	if string(siteData.CertificatePEM) != certContents {
		t.Errorf("Expected certificate %q, got %q", certContents, string(siteData.CertificatePEM))
	}
}

func TestStorageModeBundle(t *testing.T) {
	ctx := context.Background()

	// Set bundle storage mode
	originalEnv := os.Getenv(StorageModeEnv)
	defer os.Setenv(StorageModeEnv, originalEnv)
	os.Setenv(StorageModeEnv, StorageModeBundle)

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp_bundle"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(testKeyPEM),
		CertificatePEM: []byte(testCertPEM),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify bundle file exists
	issuerKey := am.IssuerKey()
	bundlePath := StorageKeys.CertificateResource(issuerKey, domain)

	if !testConfig.Storage.Exists(ctx, bundlePath) {
		t.Errorf("Expected bundle file to exist at %s", bundlePath)
	}

	// Verify legacy files do NOT exist
	keyPath := StorageKeys.SitePrivateKey(issuerKey, domain)
	certPath := StorageKeys.SiteCert(issuerKey, domain)
	metaPath := StorageKeys.SiteMeta(issuerKey, domain)

	if testConfig.Storage.Exists(ctx, keyPath) {
		t.Errorf("Expected private key file NOT to exist at %s in bundle mode", keyPath)
	}
	if testConfig.Storage.Exists(ctx, certPath) {
		t.Errorf("Expected certificate file NOT to exist at %s in bundle mode", certPath)
	}
	if testConfig.Storage.Exists(ctx, metaPath) {
		t.Errorf("Expected metadata file NOT to exist at %s in bundle mode", metaPath)
	}

	// Verify we can load it back
	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	if string(siteData.PrivateKeyPEM) != testKeyPEM {
		t.Errorf("Private key mismatch")
	}
	if string(siteData.CertificatePEM) != testCertPEM {
		t.Errorf("Certificate mismatch")
	}
}

func TestStorageModeTransition(t *testing.T) {
	ctx := context.Background()

	// Set transition storage mode
	originalEnv := os.Getenv(StorageModeEnv)
	defer os.Setenv(StorageModeEnv, originalEnv)
	os.Setenv(StorageModeEnv, StorageModeTransition)

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp_transition"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(testKeyPEM),
		CertificatePEM: []byte(testCertPEM),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify BOTH legacy and bundle files exist in transition mode
	issuerKey := am.IssuerKey()
	keyPath := StorageKeys.SitePrivateKey(issuerKey, domain)
	certPath := StorageKeys.SiteCert(issuerKey, domain)
	metaPath := StorageKeys.SiteMeta(issuerKey, domain)
	bundlePath := StorageKeys.CertificateResource(issuerKey, domain)

	if !testConfig.Storage.Exists(ctx, keyPath) {
		t.Errorf("Expected private key file to exist at %s in transition mode", keyPath)
	}
	if !testConfig.Storage.Exists(ctx, certPath) {
		t.Errorf("Expected certificate file to exist at %s in transition mode", certPath)
	}
	if !testConfig.Storage.Exists(ctx, metaPath) {
		t.Errorf("Expected metadata file to exist at %s in transition mode", metaPath)
	}
	if !testConfig.Storage.Exists(ctx, bundlePath) {
		t.Errorf("Expected bundle file to exist at %s in transition mode", bundlePath)
	}

	// Verify we can load it back (should prefer bundle)
	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	if string(siteData.PrivateKeyPEM) != testKeyPEM {
		t.Errorf("Private key mismatch")
	}
	if string(siteData.CertificatePEM) != testCertPEM {
		t.Errorf("Certificate mismatch")
	}
}

func TestStorageModeTransitionFallback(t *testing.T) {
	ctx := context.Background()

	// Set transition storage mode
	originalEnv := os.Getenv(StorageModeEnv)
	defer os.Setenv(StorageModeEnv, originalEnv)
	os.Setenv(StorageModeEnv, StorageModeTransition)

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp_transition_fallback"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	// First, save using legacy mode to simulate old data
	os.Setenv(StorageModeEnv, StorageModeLegacy)
	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error saving in legacy mode, got: %v", err)
	}

	// Verify only legacy files exist
	issuerKey := am.IssuerKey()
	keyPath := StorageKeys.SitePrivateKey(issuerKey, domain)
	bundlePath := StorageKeys.CertificateResource(issuerKey, domain)

	if !testConfig.Storage.Exists(ctx, keyPath) {
		t.Errorf("Expected private key file to exist at %s", keyPath)
	}
	if testConfig.Storage.Exists(ctx, bundlePath) {
		t.Errorf("Expected bundle file NOT to exist at %s yet", bundlePath)
	}

	// Now switch to transition mode and try to load - should fall back to legacy
	os.Setenv(StorageModeEnv, StorageModeTransition)
	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site in transition mode with fallback, got: %v", err)
	}
	if string(siteData.PrivateKeyPEM) != keyContents {
		t.Errorf("Expected private key %q, got %q", keyContents, string(siteData.PrivateKeyPEM))
	}
	if string(siteData.CertificatePEM) != certContents {
		t.Errorf("Expected certificate %q, got %q", certContents, string(siteData.CertificatePEM))
	}
}

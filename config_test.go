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

// testStorageModeSetup creates a test config with the specified storage mode
func testStorageModeSetup(t *testing.T, mode, storagePath string) (*Config, *ACMEIssuer, func()) {
	t.Helper()
	originalEnv := os.Getenv(StorageModeEnv)
	os.Setenv(StorageModeEnv, mode)

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	cfg := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: storagePath},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = cfg

	cleanup := func() {
		os.Setenv(StorageModeEnv, originalEnv)
		os.RemoveAll(storagePath)
	}

	return cfg, am, cleanup
}

// makeCertResource creates a test certificate resource
func makeCertResource(am *ACMEIssuer, domain string, useLegacyContent bool) CertificateResource {
	var keyPEM, certPEM []byte
	if useLegacyContent {
		keyPEM, certPEM = []byte("private key"), []byte("certificate")
	} else {
		keyPEM, certPEM = []byte(testKeyPEM), []byte(testCertPEM)
	}

	return CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
		IssuerData:     mustJSON(acme.Certificate{URL: "https://example.com/cert"}),
		issuerKey:      am.IssuerKey(),
	}
}

// assertFileExists checks if a file exists at the given path
func assertFileExists(t *testing.T, ctx context.Context, storage Storage, path string, shouldExist bool) {
	t.Helper()
	exists := storage.Exists(ctx, path)
	if shouldExist && !exists {
		t.Errorf("Expected file to exist at %s", path)
	} else if !shouldExist && exists {
		t.Errorf("Expected file NOT to exist at %s", path)
	}
}

// assertCertResourceContent verifies the loaded certificate matches expected content
func assertCertResourceContent(t *testing.T, loaded CertificateResource, expectedKey, expectedCert string) {
	t.Helper()
	if string(loaded.PrivateKeyPEM) != expectedKey {
		t.Errorf("Private key mismatch: expected %q, got %q", expectedKey, string(loaded.PrivateKeyPEM))
	}
	if string(loaded.CertificatePEM) != expectedCert {
		t.Errorf("Certificate mismatch: expected %q, got %q", expectedCert, string(loaded.CertificatePEM))
	}
}

func TestStorageModeLegacy(t *testing.T) {
	ctx := context.Background()
	cfg, am, cleanup := testStorageModeSetup(t, StorageModeLegacy, "./_testdata_tmp_legacy")
	defer cleanup()

	domain := "example.com"
	cert := makeCertResource(am, domain, true)

	if err := cfg.saveCertResource(ctx, am, cert); err != nil {
		t.Fatalf("Failed to save cert resource: %v", err)
	}

	issuerKey := am.IssuerKey()
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SitePrivateKey(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SiteCert(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SiteMeta(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.CertificateResource(issuerKey, domain), false)

	loaded, err := cfg.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Failed to load cert resource: %v", err)
	}
	assertCertResourceContent(t, loaded, "private key", "certificate")
}

func TestStorageModeBundle(t *testing.T) {
	ctx := context.Background()
	cfg, am, cleanup := testStorageModeSetup(t, StorageModeBundle, "./_testdata_tmp_bundle")
	defer cleanup()

	domain := "example.com"
	cert := makeCertResource(am, domain, false)

	if err := cfg.saveCertResource(ctx, am, cert); err != nil {
		t.Fatalf("Failed to save cert resource: %v", err)
	}

	issuerKey := am.IssuerKey()
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.CertificateResource(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SitePrivateKey(issuerKey, domain), false)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SiteCert(issuerKey, domain), false)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SiteMeta(issuerKey, domain), false)

	loaded, err := cfg.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Failed to load cert resource: %v", err)
	}
	assertCertResourceContent(t, loaded, testKeyPEM, testCertPEM)
}

func TestStorageModeTransition(t *testing.T) {
	ctx := context.Background()
	cfg, am, cleanup := testStorageModeSetup(t, StorageModeTransition, "./_testdata_tmp_transition")
	defer cleanup()

	domain := "example.com"
	cert := makeCertResource(am, domain, false)

	if err := cfg.saveCertResource(ctx, am, cert); err != nil {
		t.Fatalf("Failed to save cert resource: %v", err)
	}

	// Verify BOTH legacy and bundle files exist
	issuerKey := am.IssuerKey()
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SitePrivateKey(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SiteCert(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SiteMeta(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.CertificateResource(issuerKey, domain), true)

	loaded, err := cfg.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Failed to load cert resource: %v", err)
	}
	assertCertResourceContent(t, loaded, testKeyPEM, testCertPEM)
}

func TestStorageModeTransitionFallback(t *testing.T) {
	ctx := context.Background()
	cfg, am, cleanup := testStorageModeSetup(t, StorageModeTransition, "./_testdata_tmp_transition_fallback")
	defer cleanup()

	domain := "example.com"
	cert := makeCertResource(am, domain, true)

	// Save in legacy mode to simulate existing data
	os.Setenv(StorageModeEnv, StorageModeLegacy)
	if err := cfg.saveCertResource(ctx, am, cert); err != nil {
		t.Fatalf("Failed to save cert in legacy mode: %v", err)
	}

	issuerKey := am.IssuerKey()
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.SitePrivateKey(issuerKey, domain), true)
	assertFileExists(t, ctx, cfg.Storage, StorageKeys.CertificateResource(issuerKey, domain), false)

	// Switch to transition mode and verify fallback to legacy works
	os.Setenv(StorageModeEnv, StorageModeTransition)
	loaded, err := cfg.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Failed to load cert in transition mode with fallback: %v", err)
	}
	assertCertResourceContent(t, loaded, "private key", "certificate")
}

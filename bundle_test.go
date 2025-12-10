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
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestGetStorageMode(t *testing.T) {
	tests := []struct {
		envValue string
		expected StorageMode
	}{
		{"", StorageModeLegacy},
		{"legacy", StorageModeLegacy},
		{"LEGACY", StorageModeLegacy},
		{"transition", StorageModeTransition},
		{"TRANSITION", StorageModeTransition},
		{"bundle", StorageModeBundle},
		{"BUNDLE", StorageModeBundle},
		{"invalid", StorageModeLegacy},
		{"unknown", StorageModeLegacy},
	}

	for _, tt := range tests {
		t.Run(tt.envValue, func(t *testing.T) {
			os.Setenv(StorageModeEnvVar, tt.envValue)
			defer os.Unsetenv(StorageModeEnvVar)

			mode := GetStorageMode()
			if mode != tt.expected {
				t.Errorf("GetStorageMode() = %v, want %v", mode, tt.expected)
			}
		})
	}
}

func TestCertStoreLegacyMode(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}
	certStore := NewCertStoreWithMode(storage, nil, StorageModeLegacy)

	issuerKey := "test-issuer"
	domain := "example.com"
	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		IssuerData:     json.RawMessage(`{"test": "data"}`),
	}

	// Save should write to legacy format
	err := certStore.Save(ctx, issuerKey, certRes)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify legacy files exist
	if !storage.Exists(ctx, StorageKeys.SiteCert(issuerKey, domain)) {
		t.Error("legacy .crt file should exist")
	}
	if !storage.Exists(ctx, StorageKeys.SitePrivateKey(issuerKey, domain)) {
		t.Error("legacy .key file should exist")
	}
	if !storage.Exists(ctx, StorageKeys.SiteMeta(issuerKey, domain)) {
		t.Error("legacy .json file should exist")
	}

	// Verify bundle file does NOT exist
	if storage.Exists(ctx, StorageKeys.SiteBundle(issuerKey, domain)) {
		t.Error("bundle file should NOT exist in legacy mode")
	}

	// Load should work
	loaded, err := certStore.Load(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(loaded.CertificatePEM) != string(certRes.CertificatePEM) {
		t.Error("loaded certificate doesn't match")
	}

	// Exists should return true
	if !certStore.Exists(ctx, issuerKey, domain) {
		t.Error("Exists() should return true")
	}

	// Delete should remove legacy files
	err = certStore.Delete(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if storage.Exists(ctx, StorageKeys.SiteCert(issuerKey, domain)) {
		t.Error("legacy .crt file should be deleted")
	}
}

func TestCertStoreBundleMode(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}
	certStore := NewCertStoreWithMode(storage, nil, StorageModeBundle)

	issuerKey := "test-issuer"
	domain := "example.com"
	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		IssuerData:     json.RawMessage(`{"test": "data"}`),
	}

	// Save should write to bundle format
	err := certStore.Save(ctx, issuerKey, certRes)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify bundle file exists
	if !storage.Exists(ctx, StorageKeys.SiteBundle(issuerKey, domain)) {
		t.Error("bundle file should exist")
	}

	// Verify legacy files do NOT exist
	if storage.Exists(ctx, StorageKeys.SiteCert(issuerKey, domain)) {
		t.Error("legacy .crt file should NOT exist in bundle mode")
	}

	// Load should work
	loaded, err := certStore.Load(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(loaded.CertificatePEM) != string(certRes.CertificatePEM) {
		t.Error("loaded certificate doesn't match")
	}

	// Exists should return true
	if !certStore.Exists(ctx, issuerKey, domain) {
		t.Error("Exists() should return true")
	}

	// Delete should remove bundle file
	err = certStore.Delete(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if storage.Exists(ctx, StorageKeys.SiteBundle(issuerKey, domain)) {
		t.Error("bundle file should be deleted")
	}
}

func TestCertStoreTransitionMode(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}
	certStore := NewCertStoreWithMode(storage, nil, StorageModeTransition)

	issuerKey := "test-issuer"
	domain := "example.com"
	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		IssuerData:     json.RawMessage(`{"test": "data"}`),
	}

	// Save should write to BOTH formats
	err := certStore.Save(ctx, issuerKey, certRes)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify bundle file exists
	if !storage.Exists(ctx, StorageKeys.SiteBundle(issuerKey, domain)) {
		t.Error("bundle file should exist in transition mode")
	}

	// Verify legacy files also exist
	if !storage.Exists(ctx, StorageKeys.SiteCert(issuerKey, domain)) {
		t.Error("legacy .crt file should exist in transition mode")
	}
	if !storage.Exists(ctx, StorageKeys.SitePrivateKey(issuerKey, domain)) {
		t.Error("legacy .key file should exist in transition mode")
	}
	if !storage.Exists(ctx, StorageKeys.SiteMeta(issuerKey, domain)) {
		t.Error("legacy .json file should exist in transition mode")
	}

	// Load should prefer bundle format
	loaded, err := certStore.Load(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(loaded.CertificatePEM) != string(certRes.CertificatePEM) {
		t.Error("loaded certificate doesn't match")
	}
}

func TestCertStoreMigration(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}

	issuerKey := "test-issuer"
	domain := "example.com"
	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		IssuerData:     json.RawMessage(`{"test": "data"}`),
	}

	// First, save in legacy mode
	legacyStore := NewCertStoreWithMode(storage, nil, StorageModeLegacy)
	err := legacyStore.Save(ctx, issuerKey, certRes)
	if err != nil {
		t.Fatalf("Save() in legacy mode error = %v", err)
	}

	// Verify only legacy files exist
	if storage.Exists(ctx, StorageKeys.SiteBundle(issuerKey, domain)) {
		t.Error("bundle file should NOT exist before migration")
	}
	if !storage.Exists(ctx, StorageKeys.SiteCert(issuerKey, domain)) {
		t.Error("legacy .crt file should exist before migration")
	}

	// Now migrate
	bundleStore := NewCertStoreWithMode(storage, nil, StorageModeBundle)
	err = bundleStore.Migrate(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// Verify bundle file exists after migration
	if !storage.Exists(ctx, StorageKeys.SiteBundle(issuerKey, domain)) {
		t.Error("bundle file should exist after migration")
	}

	// Verify legacy files are cleaned up
	if storage.Exists(ctx, StorageKeys.SiteCert(issuerKey, domain)) {
		t.Error("legacy .crt file should be cleaned up after migration")
	}

	// Verify data is preserved
	loaded, err := bundleStore.Load(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Load() after migration error = %v", err)
	}
	if string(loaded.CertificatePEM) != string(certRes.CertificatePEM) {
		t.Error("certificate data not preserved after migration")
	}
	if string(loaded.PrivateKeyPEM) != string(certRes.PrivateKeyPEM) {
		t.Error("private key data not preserved after migration")
	}
}

func TestCertStoreBundleModeWithLegacyFallback(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}

	issuerKey := "test-issuer"
	domain := "example.com"
	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		IssuerData:     json.RawMessage(`{"test": "data"}`),
	}

	// Save in legacy mode (simulating pre-migration data)
	legacyStore := NewCertStoreWithMode(storage, nil, StorageModeLegacy)
	err := legacyStore.Save(ctx, issuerKey, certRes)
	if err != nil {
		t.Fatalf("Save() in legacy mode error = %v", err)
	}

	// Now try to load in bundle mode (should fall back to legacy)
	bundleStore := NewCertStoreWithMode(storage, nil, StorageModeBundle)
	loaded, err := bundleStore.Load(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Load() in bundle mode with legacy fallback error = %v", err)
	}
	if string(loaded.CertificatePEM) != string(certRes.CertificatePEM) {
		t.Error("loaded certificate doesn't match")
	}

	// Exists should also work with fallback
	if !bundleStore.Exists(ctx, issuerKey, domain) {
		t.Error("Exists() should return true with legacy fallback")
	}
}

func TestCertStoreUpdateMetadata(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}
	certStore := NewCertStoreWithMode(storage, nil, StorageModeBundle)

	issuerKey := "test-issuer"
	domain := "example.com"
	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"),
		IssuerData:     json.RawMessage(`{"original": "data"}`),
	}

	// Save initial
	err := certStore.Save(ctx, issuerKey, certRes)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Update metadata
	err = certStore.UpdateMetadata(ctx, issuerKey, domain, func(current json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"updated": "metadata"}`), nil
	})
	if err != nil {
		t.Fatalf("UpdateMetadata() error = %v", err)
	}

	// Load and verify metadata was updated
	loaded, err := certStore.Load(ctx, issuerKey, domain)
	if err != nil {
		t.Fatalf("Load() after UpdateMetadata error = %v", err)
	}
	// Parse JSON for comparison to ignore formatting differences
	var gotMeta, wantMeta map[string]string
	if err := json.Unmarshal(loaded.IssuerData, &gotMeta); err != nil {
		t.Fatalf("failed to parse loaded IssuerData: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"updated": "metadata"}`), &wantMeta); err != nil {
		t.Fatalf("failed to parse expected IssuerData: %v", err)
	}
	if gotMeta["updated"] != wantMeta["updated"] {
		t.Errorf("IssuerData = %v, want %v", gotMeta, wantMeta)
	}

	// Verify certificate and key are unchanged
	if string(loaded.CertificatePEM) != string(certRes.CertificatePEM) {
		t.Error("certificate should be unchanged after metadata update")
	}
	if string(loaded.PrivateKeyPEM) != string(certRes.PrivateKeyPEM) {
		t.Error("private key should be unchanged after metadata update")
	}
}

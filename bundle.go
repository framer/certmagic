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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/idna"
)

// StorageMode determines how certificates are stored and loaded.
type StorageMode string

const (
	// StorageModeLegacy uses only the legacy 3-file format (.crt, .key, .json).
	// This is the default mode for full backward compatibility.
	StorageModeLegacy StorageMode = "legacy"

	// StorageModeTransition reads from bundle format first (with legacy fallback),
	// and writes to BOTH formats. This allows safe rollback during migration.
	StorageModeTransition StorageMode = "transition"

	// StorageModeBundle reads from bundle format first (with legacy fallback),
	// and writes only to bundle format. Legacy files are cleaned up after writing.
	StorageModeBundle StorageMode = "bundle"
)

// StorageModeEnvVar is the environment variable name used to set the storage mode.
const StorageModeEnvVar = "CERTMAGIC_STORAGE_MODE"

// GetStorageMode returns the current storage mode from the environment variable.
// If not set or invalid, it defaults to StorageModeLegacy.
func GetStorageMode() StorageMode {
	mode := StorageMode(strings.ToLower(os.Getenv(StorageModeEnvVar)))
	switch mode {
	case StorageModeLegacy, StorageModeTransition, StorageModeBundle:
		return mode
	default:
		return StorageModeLegacy
	}
}

// BundleVersion is the current certificate bundle format version.
// This allows for future format evolution while maintaining backward compatibility.
const BundleVersion = 1

// CertificateBundle is the unified storage format that combines certificate,
// private key, and metadata into a single file. This provides atomic writes
// and simplifies storage operations.
type CertificateBundle struct {
	// Version of the bundle format (for future compatibility)
	Version int `json:"version"`

	// SANs are the Subject Alternative Names on the certificate
	SANs []string `json:"sans,omitempty"`

	// CertificatePEM is the PEM-encoded certificate chain
	CertificatePEM []byte `json:"certificate_pem"`

	// PrivateKeyPEM is the PEM-encoded private key
	PrivateKeyPEM []byte `json:"private_key_pem"`

	// IssuerData contains issuer-specific metadata (e.g., ACME cert info, ARI)
	IssuerData json.RawMessage `json:"issuer_data,omitempty"`

	// CreatedAt is when this bundle was first created
	CreatedAt time.Time `json:"created_at,omitempty"`

	// UpdatedAt is when this bundle was last updated
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// CertStore abstracts all certificate storage operations, providing a clean
// interface for saving, loading, and managing certificate bundles. It handles
// the transition from the legacy 3-file format to the new bundle format.
type CertStore struct {
	storage Storage
	logger  *zap.Logger
	mode    StorageMode
}

// NewCertStore creates a new CertStore with the given storage backend and logger.
// The storage mode is determined by the CERTMAGIC_STORAGE_MODE environment variable.
func NewCertStore(storage Storage, logger *zap.Logger) *CertStore {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CertStore{
		storage: storage,
		logger:  logger,
		mode:    GetStorageMode(),
	}
}

// NewCertStoreWithMode creates a new CertStore with an explicit storage mode.
// This is useful for testing or when the mode needs to be set programmatically.
func NewCertStoreWithMode(storage Storage, logger *zap.Logger, mode StorageMode) *CertStore {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CertStore{
		storage: storage,
		logger:  logger,
		mode:    mode,
	}
}

// Save writes a certificate resource to storage according to the configured storage mode:
//   - legacy: writes only to 3-file format
//   - transition: writes to both bundle and 3-file format (for safe rollback)
//   - bundle: writes only to bundle format (and cleans up legacy files)
func (cs *CertStore) Save(ctx context.Context, issuerKey string, res CertificateResource) error {
	certKey := res.NamesKey()

	switch cs.mode {
	case StorageModeLegacy:
		return cs.saveLegacy(ctx, issuerKey, certKey, res)

	case StorageModeTransition:
		// Write to both formats for safe rollback
		if err := cs.saveBundle(ctx, issuerKey, certKey, res); err != nil {
			return err
		}
		return cs.saveLegacy(ctx, issuerKey, certKey, res)

	case StorageModeBundle:
		if err := cs.saveBundle(ctx, issuerKey, certKey, res); err != nil {
			return err
		}
		// Clean up legacy files if they exist
		cs.deleteLegacyFiles(ctx, issuerKey, certKey)
		return nil

	default:
		return cs.saveLegacy(ctx, issuerKey, certKey, res)
	}
}

// saveBundle writes a certificate resource as a single bundle file.
func (cs *CertStore) saveBundle(ctx context.Context, issuerKey, certKey string, res CertificateResource) error {
	bundle := CertificateBundle{
		Version:        BundleVersion,
		SANs:           res.SANs,
		CertificatePEM: res.CertificatePEM,
		PrivateKeyPEM:  res.PrivateKeyPEM,
		IssuerData:     res.IssuerData,
		UpdatedAt:      time.Now().UTC(),
	}

	// Check if this is an update to an existing bundle
	bundleKey := StorageKeys.SiteBundle(issuerKey, certKey)
	if existingData, err := cs.storage.Load(ctx, bundleKey); err == nil {
		var existing CertificateBundle
		if json.Unmarshal(existingData, &existing) == nil {
			bundle.CreatedAt = existing.CreatedAt
		}
	}
	if bundle.CreatedAt.IsZero() {
		bundle.CreatedAt = bundle.UpdatedAt
	}

	bundleBytes, err := json.MarshalIndent(bundle, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding certificate bundle: %v", err)
	}

	if err := cs.storage.Store(ctx, bundleKey, bundleBytes); err != nil {
		return fmt.Errorf("storing certificate bundle: %v", err)
	}

	return nil
}

// saveLegacy writes a certificate resource as 3 separate files (legacy format).
func (cs *CertStore) saveLegacy(ctx context.Context, issuerKey, certKey string, res CertificateResource) error {
	metaBytes, err := json.MarshalIndent(CertificateResource{
		SANs:       res.SANs,
		IssuerData: res.IssuerData,
	}, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding certificate metadata: %v", err)
	}

	all := []keyValue{
		{
			key:   StorageKeys.SitePrivateKey(issuerKey, certKey),
			value: res.PrivateKeyPEM,
		},
		{
			key:   StorageKeys.SiteCert(issuerKey, certKey),
			value: res.CertificatePEM,
		},
		{
			key:   StorageKeys.SiteMeta(issuerKey, certKey),
			value: metaBytes,
		},
	}

	return storeTx(ctx, cs.storage, all)
}

// Load reads a certificate resource according to the configured storage mode:
//   - legacy: reads only from 3-file format
//   - transition/bundle: tries bundle format first, falls back to 3-file format
func (cs *CertStore) Load(ctx context.Context, issuerKey, certNamesKey string) (CertificateResource, error) {
	// Normalize the name
	normalizedName, err := idna.ToASCII(certNamesKey)
	if err != nil {
		return CertificateResource{}, fmt.Errorf("converting '%s' to ASCII: %v", certNamesKey, err)
	}

	switch cs.mode {
	case StorageModeLegacy:
		// Only read from legacy format
		return cs.loadLegacy(ctx, issuerKey, normalizedName)

	case StorageModeTransition, StorageModeBundle:
		// Try new bundle format first
		bundleKey := StorageKeys.SiteBundle(issuerKey, normalizedName)
		if bundleData, err := cs.storage.Load(ctx, bundleKey); err == nil {
			return cs.decodeBundle(bundleData, issuerKey)
		}
		// Fall back to legacy 3-file format
		return cs.loadLegacy(ctx, issuerKey, normalizedName)

	default:
		return cs.loadLegacy(ctx, issuerKey, normalizedName)
	}
}

// Exists checks if a certificate exists in storage according to the configured storage mode:
//   - legacy: checks only 3-file format
//   - transition/bundle: checks bundle format first, then 3-file format
func (cs *CertStore) Exists(ctx context.Context, issuerKey, domain string) bool {
	normalizedName, err := idna.ToASCII(domain)
	if err != nil {
		return false
	}

	// Check legacy format (all 3 files must exist)
	legacyExists := func() bool {
		certKey := StorageKeys.SiteCert(issuerKey, normalizedName)
		keyKey := StorageKeys.SitePrivateKey(issuerKey, normalizedName)
		metaKey := StorageKeys.SiteMeta(issuerKey, normalizedName)
		return cs.storage.Exists(ctx, certKey) &&
			cs.storage.Exists(ctx, keyKey) &&
			cs.storage.Exists(ctx, metaKey)
	}

	switch cs.mode {
	case StorageModeLegacy:
		return legacyExists()

	case StorageModeTransition, StorageModeBundle:
		// Check bundle format first
		bundleKey := StorageKeys.SiteBundle(issuerKey, normalizedName)
		if cs.storage.Exists(ctx, bundleKey) {
			return true
		}
		// Fall back to legacy format
		return legacyExists()

	default:
		return legacyExists()
	}
}

// Delete removes a certificate from storage according to the configured storage mode.
// In all modes, both bundle and legacy files are deleted to ensure complete cleanup.
func (cs *CertStore) Delete(ctx context.Context, issuerKey, domain string) error {
	normalizedName, err := idna.ToASCII(domain)
	if err != nil {
		return fmt.Errorf("converting '%s' to ASCII: %v", domain, err)
	}

	var errs []error

	// Always try to delete both formats to ensure complete cleanup
	// (a certificate might have been created in a different mode)

	// Delete bundle format
	bundleKey := StorageKeys.SiteBundle(issuerKey, normalizedName)
	if cs.storage.Exists(ctx, bundleKey) {
		if err := cs.storage.Delete(ctx, bundleKey); err != nil {
			errs = append(errs, fmt.Errorf("deleting bundle: %v", err))
		}
	}

	// Delete legacy files
	cs.deleteLegacyFiles(ctx, issuerKey, normalizedName)

	// Delete the site folder if empty
	sitePrefix := StorageKeys.CertsSitePrefix(issuerKey, normalizedName)
	if cs.storage.Exists(ctx, sitePrefix) {
		if err := cs.storage.Delete(ctx, sitePrefix); err != nil {
			// Not a critical error - folder might not be empty
			cs.logger.Debug("could not delete site folder", zap.String("path", sitePrefix), zap.Error(err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// UpdateMetadata atomically updates only the metadata (IssuerData) portion of
// a certificate bundle. This is useful for ARI updates where only the metadata
// changes but the certificate and key remain the same.
func (cs *CertStore) UpdateMetadata(ctx context.Context, issuerKey, domain string,
	updateFn func(current json.RawMessage) (json.RawMessage, error)) error {

	normalizedName, err := idna.ToASCII(domain)
	if err != nil {
		return fmt.Errorf("converting '%s' to ASCII: %v", domain, err)
	}

	// Load the current bundle
	certRes, err := cs.Load(ctx, issuerKey, normalizedName)
	if err != nil {
		return fmt.Errorf("loading certificate for metadata update: %v", err)
	}

	// Apply the update function
	newIssuerData, err := updateFn(certRes.IssuerData)
	if err != nil {
		return fmt.Errorf("updating metadata: %v", err)
	}
	certRes.IssuerData = newIssuerData

	// Save the updated bundle
	return cs.Save(ctx, issuerKey, certRes)
}

// LoadPrivateKey loads only the private key for a certificate. This is used
// when reusing private keys across certificate renewals.
func (cs *CertStore) LoadPrivateKey(ctx context.Context, issuerKey, domain string) ([]byte, error) {
	normalizedName, err := idna.ToASCII(domain)
	if err != nil {
		return nil, fmt.Errorf("converting '%s' to ASCII: %v", domain, err)
	}

	switch cs.mode {
	case StorageModeLegacy:
		keyKey := StorageKeys.SitePrivateKey(issuerKey, normalizedName)
		return cs.storage.Load(ctx, keyKey)

	case StorageModeTransition, StorageModeBundle:
		// Try bundle format first
		bundleKey := StorageKeys.SiteBundle(issuerKey, normalizedName)
		if bundleData, err := cs.storage.Load(ctx, bundleKey); err == nil {
			var bundle CertificateBundle
			if err := json.Unmarshal(bundleData, &bundle); err != nil {
				return nil, fmt.Errorf("decoding bundle: %v", err)
			}
			return bundle.PrivateKeyPEM, nil
		}
		// Fall back to legacy format
		keyKey := StorageKeys.SitePrivateKey(issuerKey, normalizedName)
		return cs.storage.Load(ctx, keyKey)

	default:
		keyKey := StorageKeys.SitePrivateKey(issuerKey, normalizedName)
		return cs.storage.Load(ctx, keyKey)
	}
}

// MoveCompromisedKey moves a compromised private key to a ".compromised" location
// and removes it from the certificate storage.
func (cs *CertStore) MoveCompromisedKey(ctx context.Context, issuerKey, domain string) error {
	normalizedName, err := idna.ToASCII(domain)
	if err != nil {
		return fmt.Errorf("converting '%s' to ASCII: %v", domain, err)
	}

	// Load the private key
	privKeyPEM, err := cs.LoadPrivateKey(ctx, issuerKey, normalizedName)
	if err != nil {
		return fmt.Errorf("loading private key: %v", err)
	}

	// Save to compromised location (use appropriate path based on mode)
	var compromisedKey string
	switch cs.mode {
	case StorageModeLegacy:
		compromisedKey = StorageKeys.SitePrivateKey(issuerKey, normalizedName) + ".compromised"
	default:
		compromisedKey = StorageKeys.SiteBundle(issuerKey, normalizedName) + ".compromised"
	}

	if err := cs.storage.Store(ctx, compromisedKey, privKeyPEM); err != nil {
		return fmt.Errorf("storing compromised key: %v", err)
	}

	// Delete the certificate entirely (forces re-obtain with new key)
	if err := cs.Delete(ctx, issuerKey, normalizedName); err != nil {
		return fmt.Errorf("deleting certificate with compromised key: %v", err)
	}

	cs.logger.Info("moved compromised private key",
		zap.String("domain", domain),
		zap.String("issuer", issuerKey),
		zap.String("compromised_path", compromisedKey))

	return nil
}

// decodeBundle decodes a bundle from JSON bytes into a CertificateResource.
func (cs *CertStore) decodeBundle(data []byte, issuerKey string) (CertificateResource, error) {
	var bundle CertificateBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return CertificateResource{}, fmt.Errorf("decoding certificate bundle: %v", err)
	}

	// Handle future version upgrades here if needed
	if bundle.Version > BundleVersion {
		cs.logger.Warn("bundle version is newer than supported",
			zap.Int("bundle_version", bundle.Version),
			zap.Int("supported_version", BundleVersion))
	}

	return CertificateResource{
		SANs:           bundle.SANs,
		CertificatePEM: bundle.CertificatePEM,
		PrivateKeyPEM:  bundle.PrivateKeyPEM,
		IssuerData:     bundle.IssuerData,
		issuerKey:      issuerKey,
	}, nil
}

// loadLegacy loads a certificate from the legacy 3-file format.
func (cs *CertStore) loadLegacy(ctx context.Context, issuerKey, normalizedName string) (CertificateResource, error) {
	certRes := CertificateResource{issuerKey: issuerKey}

	keyBytes, err := cs.storage.Load(ctx, StorageKeys.SitePrivateKey(issuerKey, normalizedName))
	if err != nil {
		return CertificateResource{}, err
	}
	certRes.PrivateKeyPEM = keyBytes

	certBytes, err := cs.storage.Load(ctx, StorageKeys.SiteCert(issuerKey, normalizedName))
	if err != nil {
		return CertificateResource{}, err
	}
	certRes.CertificatePEM = certBytes

	metaBytes, err := cs.storage.Load(ctx, StorageKeys.SiteMeta(issuerKey, normalizedName))
	if err != nil {
		return CertificateResource{}, err
	}

	if err := json.Unmarshal(metaBytes, &certRes); err != nil {
		return CertificateResource{}, fmt.Errorf("decoding certificate metadata: %v", err)
	}

	return certRes, nil
}

// deleteLegacyFiles removes the legacy 3-file format files if they exist.
// Errors are logged but not returned since this is a cleanup operation.
func (cs *CertStore) deleteLegacyFiles(ctx context.Context, issuerKey, certKey string) {
	legacyFiles := []string{
		StorageKeys.SiteCert(issuerKey, certKey),
		StorageKeys.SitePrivateKey(issuerKey, certKey),
		StorageKeys.SiteMeta(issuerKey, certKey),
	}

	for _, key := range legacyFiles {
		if cs.storage.Exists(ctx, key) {
			if err := cs.storage.Delete(ctx, key); err != nil {
				cs.logger.Debug("could not delete legacy file",
					zap.String("key", key),
					zap.Error(err))
			} else {
				cs.logger.Debug("deleted legacy file", zap.String("key", key))
			}
		}
	}
}

// Migrate converts a certificate from the legacy 3-file format to the new
// bundle format. This is useful for batch migration of existing certificates.
// Note: This method ignores the storage mode and always writes to bundle format.
// Use this for explicit migration operations.
func (cs *CertStore) Migrate(ctx context.Context, issuerKey, domain string) error {
	normalizedName, err := idna.ToASCII(domain)
	if err != nil {
		return fmt.Errorf("converting '%s' to ASCII: %v", domain, err)
	}

	// Check if already migrated
	bundleKey := StorageKeys.SiteBundle(issuerKey, normalizedName)
	if cs.storage.Exists(ctx, bundleKey) {
		return nil // Already migrated
	}

	// Check if legacy exists
	if !cs.storage.Exists(ctx, StorageKeys.SiteCert(issuerKey, normalizedName)) {
		return fs.ErrNotExist
	}

	// Load from legacy
	certRes, err := cs.loadLegacy(ctx, issuerKey, normalizedName)
	if err != nil {
		return fmt.Errorf("loading legacy certificate: %v", err)
	}

	// Save as bundle
	if err := cs.saveBundle(ctx, issuerKey, normalizedName, certRes); err != nil {
		return fmt.Errorf("saving as bundle: %v", err)
	}

	// Clean up legacy files after successful migration
	cs.deleteLegacyFiles(ctx, issuerKey, normalizedName)

	cs.logger.Info("migrated certificate to bundle format",
		zap.String("domain", domain),
		zap.String("issuer", issuerKey))

	return nil
}

// MigrateAll migrates all certificates for a given issuer to bundle format.
// This scans for legacy site folders and migrates each certificate found.
func (cs *CertStore) MigrateAll(ctx context.Context, issuerKey string) error {
	certsPrefix := StorageKeys.CertsPrefix(issuerKey)
	items, err := cs.storage.List(ctx, certsPrefix, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // No certificates to migrate
		}
		return fmt.Errorf("listing certificates: %v", err)
	}

	var migrated, skipped, failed int
	for _, itemKey := range items {
		// Skip if it's already a bundle file
		if strings.HasSuffix(itemKey, ".bundle.json") {
			skipped++
			continue
		}

		// Extract domain from path (site folder name)
		domain := itemKey[len(certsPrefix)+1:] // +1 for the slash

		err := cs.Migrate(ctx, issuerKey, domain)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				skipped++
				continue
			}
			cs.logger.Error("failed to migrate certificate",
				zap.String("domain", domain),
				zap.Error(err))
			failed++
			continue
		}
		migrated++
	}

	cs.logger.Info("migration complete",
		zap.String("issuer", issuerKey),
		zap.Int("migrated", migrated),
		zap.Int("skipped", skipped),
		zap.Int("failed", failed))

	return nil
}

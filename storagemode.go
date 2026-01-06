package certmagic

import (
	"hash/fnv"
	"os"
	"strconv"
)

const (
	// Storage mode controls the format in which certificates are stored in `Storage`.
	//
	// Formats:
	// - legacy: Store cert, privkey and meta as three separate storage items (.cert, .key, .json).
	// - bundle: Store cert, privkey and meta as a single, bundled storage item (.bundle).
	//
	// Modes:
	// - legacy:     Store and load certificates in legacy format.
	// - transition: Store in legacy and bundle format, load as bundle with fallback to legacy format.
	// - bundle:      Store and load certificates in bundle format.
	//
	// In the transition mode, failures around reads and writes of the bundle are soft.
	// They should only log errors and try to work with the legacy format as fallback.
	// Operations on the legacy format are hard-failures, implying that errors should be propagated up.
	//
	// The rollout percentage enables a phased migration by controlling which domains
	// enter the transition phase. If a domain's deterministic bucket (0-99) is below
	// the rollout percentage, it uses 'transition' mode (dual-write, bundle-read).
	// Otherwise, it remains in 'legacy' mode.
	//
	// The logic for selection is:
	//   if mode == StorageModeTransition:
	//       useTransition = hash(domain)%100 < rollout
	//       return useTransition ? StorageModeTransition : StorageModeLegacy
	//
	// The storage mode is controlled via the CERTMAGIC_STORAGE_MODE environment variable
	StorageModeEnv = "CERTMAGIC_STORAGE_MODE"

	StorageModeLegacy     = "legacy"
	StorageModeTransition = "transition"
	StorageModeBundle     = "bundle"

	// StorageModeRolloutPercentEnv controls the percentage of domains that will use
	// the bundle format when the storage mode is set to "transition".
	// An empty rollout precent is equal to 0%.
	StorageModeRolloutPercentEnv = "CERTMAGIC_STORAGE_MODE_ROLLOUT_PERCENT"
)

var (
	StorageMode               string
	StorageModeRolloutPercent int
)

func ConfigureStorageMode(mode string, rolloutPercent int) {
	StorageMode = mode
	StorageModeRolloutPercent = rolloutPercent
}

func init() {
	mode := os.Getenv(StorageModeEnv)

	// rolloutPercent becomes zero if env is unset or malformed
	rolloutPercent, _ := strconv.Atoi(os.Getenv(StorageModeRolloutPercentEnv))

	ConfigureStorageMode(mode, rolloutPercent)
}

func StorageModeForDomain(domain string) string {
	if StorageMode == StorageModeBundle {
		return StorageModeBundle
	}
	if StorageMode != StorageModeTransition {
		return StorageModeLegacy
	}
	if RolloutBucketForDomain(domain) < StorageModeRolloutPercent {
		return StorageModeTransition
	} else {
		return StorageModeLegacy
	}
}

func RolloutBucketForDomain(domain string) int {
	h := fnv.New32a()
	h.Write([]byte(domain))
	return int(h.Sum32() % 100)
}

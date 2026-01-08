package certmagic

import "testing"

func TestStorageModeRolloutPercentLegacy(t *testing.T) {
	// In legacy mode, storage mode for all domains must be "legacy", no matter the rollout percent.
	for _, rolloutPercent := range []int{0, 50, 100} {
		ConfigureStorageMode(StorageModeLegacy, rolloutPercent)

		for _, domain := range []string{"cyufsv.com", "lgxeeu.com", "msngsw.com"} {
			if got := StorageModeForDomain(domain); got != StorageModeLegacy {
				t.Errorf("rollout %d%%, StorageModeForDomain(%q) = %q, want %q",
					rolloutPercent, domain, got, StorageModeLegacy)
			}
		}
	}
}

func TestStorageModeRolloutPercentBundle(t *testing.T) {
	// In bundle mode, storage mode for all domains must be "bundle", no matter the rollout percent.
	for _, rolloutPercent := range []int{0, 50, 100} {
		ConfigureStorageMode(StorageModeBundle, rolloutPercent)

		for _, domain := range []string{"cyufsv.com", "lgxeeu.com", "msngsw.com"} {
			if got := StorageModeForDomain(domain); got != StorageModeBundle {
				t.Errorf("rollout %d%%, StorageModeForDomain(%q) = %q, want %q",
					rolloutPercent, domain, got, StorageModeBundle)
			}
		}
	}
}

func TestStorageModeRolloutPercentTransition(t *testing.T) {
	// In transition mode, storage mode for domains can either be "transition" or "legacy", depending on rollout percent.
	// Domains are assigned to buckets 0-99 based on their hash. A domain enters transition mode
	// if its bucket is below the rollout percent.
	//
	// Test domains and their buckets:
	//   "cyufsv.com" -> bucket 0
	//   "wrgmsg.com" -> bucket 1
	//   "cdbbdh.com" -> bucket 49
	//   "lgxeeu.com" -> bucket 50
	//   "hwqhre.com" -> bucket 51
	//   "ckycee.com" -> bucket 98
	//   "msngsw.com" -> bucket 99
	tests := []struct {
		name           string
		rolloutPercent int
		domain         string
		domainBucket   int
		want           string
	}{
		// 0% rollout: no domains should transition
		{"0% rollout, bucket 0", 0, "cyufsv.com", 0, StorageModeLegacy},
		{"0% rollout, bucket 50", 0, "lgxeeu.com", 50, StorageModeLegacy},
		{"0% rollout, bucket 99", 0, "msngsw.com", 99, StorageModeLegacy},

		// 100% rollout: all domains should transition
		{"100% rollout, bucket 0", 100, "cyufsv.com", 0, StorageModeTransition},
		{"100% rollout, bucket 50", 100, "lgxeeu.com", 50, StorageModeTransition},
		{"100% rollout, bucket 99", 100, "msngsw.com", 99, StorageModeTransition},

		// Edge cases: bucket exactly at rollout boundary
		{"50% rollout, bucket 49 (just below)", 50, "cdbbdh.com", 49, StorageModeTransition},
		{"50% rollout, bucket 50 (exactly at)", 50, "lgxeeu.com", 50, StorageModeLegacy},
		{"50% rollout, bucket 51 (just above)", 50, "hwqhre.com", 51, StorageModeLegacy},

		// Edge cases at boundaries
		{"1% rollout, bucket 0", 1, "cyufsv.com", 0, StorageModeTransition},
		{"1% rollout, bucket 1", 1, "wrgmsg.com", 1, StorageModeLegacy},
		{"99% rollout, bucket 98", 99, "ckycee.com", 98, StorageModeTransition},
		{"99% rollout, bucket 99", 99, "msngsw.com", 99, StorageModeLegacy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ConfigureStorageMode(StorageModeTransition, tt.rolloutPercent)
			if got := StorageModeForDomain(tt.domain); got != tt.want {
				t.Errorf("StorageModeForDomain(%q) = %q, want %q (bucket %d, rollout %d%%)",
					tt.domain, got, tt.want, tt.domainBucket, tt.rolloutPercent)
			}
		})
	}
}

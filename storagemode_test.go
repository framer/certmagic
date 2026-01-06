package certmagic

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestStorageModeRolloutPercentLegacy(t *testing.T) {
	// In legacy mode, storage mode for all domains must be "legacy", no matter the rollout percent.
	// This test brute-forces all possible test cases, as they are cheap to assert.
	for rolloutPercent := range 100 {
		ConfigureStorageMode(StorageModeLegacy, rolloutPercent)

		for _, domain := range testStorageModeDomains {
			want, got := StorageModeLegacy, StorageModeForDomain(domain)
			if want != got {
				t.Errorf("expected storage mode %q for domain %q, got: %q", want, domain, got)
			}
		}
	}
}

func TestStorageModeRolloutPercentBundle(t *testing.T) {
	// In legacy mode, storage mode for all domains must be "legacy", no matter the rollout percent.
	// This test brute-forces all possible test cases, as they are cheap to assert.
	for rolloutPercent := range 100 {
		ConfigureStorageMode(StorageModeBundle, rolloutPercent)

		for _, domain := range testStorageModeDomains {
			want, got := StorageModeBundle, StorageModeForDomain(domain)
			if want != got {
				t.Errorf("expected storage mode %q for domain %q, got: %q", want, domain, got)
			}
		}
	}
}

func TestStorageModeRolloutPercentTransition(t *testing.T) {
	// In transition mode, storage mode for domains can either be "transition" or "legacy", depending on rollout percent.
	// This test brute-forces all possible test cases, as they are cheap to assert.
	for rolloutPercent := range 100 {
		ConfigureStorageMode(StorageModeTransition, rolloutPercent)

		for domainBucket, domain := range testStorageModeDomains {
			got := StorageModeForDomain(domain)

			var want string
			if domainBucket < rolloutPercent {
				want = StorageModeTransition
			} else {
				want = StorageModeLegacy
			}

			if want != got {
				t.Errorf("expected storage mode %q for domain %q, got: %q", want, domain, got)
			}
		}
	}
}

func GenerateRandomDomainsForRolloutBuckets(t *testing.T) {
	for desiredBucket := range 100 {
		for {
			domain := RandomDomain()
			bucket := RolloutBucketForDomain(domain)
			if desiredBucket == bucket {
				fmt.Println(domain, bucket)
				break
			}
		}
	}
}

func RandomDomain() string {
	alphabet := "abcdefghijklmnopqrstuvwxyz"
	src := make([]byte, 6)
	rand.Read(src)
	for i := range src {
		src[i] = alphabet[src[i]%26]
	}
	return string(src) + ".com"
}

// testStorageModeDomains are domains whose hashes are deterministic.
// Example:
// - Domain at index 0 hashes to bucket 0
// - Domain at index 1 hashes to bucket 1
// - Domain at index 2 hashes to bucket 2
// - ...
var testStorageModeDomains = []string{
	"cyufsv.com",
	"wrgmsg.com",
	"brgdjo.com",
	"ydwcck.com",
	"mflmhz.com",
	"haegjj.com",
	"zmhovf.com",
	"obufpu.com",
	"feslvv.com",
	"sebycw.com",
	"eilifq.com",
	"hqbrqi.com",
	"msdfdl.com",
	"zzyzeg.com",
	"omkufr.com",
	"wxknzs.com",
	"sbrjrs.com",
	"oirmum.com",
	"ahkfmk.com",
	"pasrgp.com",
	"wkxoax.com",
	"hrften.com",
	"awvybq.com",
	"sdnroo.com",
	"oihglq.com",
	"ilomtn.com",
	"jsslsa.com",
	"xfqsqj.com",
	"seccht.com",
	"kdggrx.com",
	"htueua.com",
	"rwnblj.com",
	"muuiye.com",
	"dmgdwl.com",
	"ehcpua.com",
	"hheskv.com",
	"xapqrp.com",
	"rtqlga.com",
	"zwejrb.com",
	"caijym.com",
	"qqobjq.com",
	"ylhtvl.com",
	"leotig.com",
	"xzzdkn.com",
	"gtbrls.com",
	"ffdfon.com",
	"yndvoz.com",
	"pcdete.com",
	"mqqawg.com",
	"cdbbdh.com",
	"lgxeeu.com",
	"hwqhre.com",
	"glzlpq.com",
	"wmogra.com",
	"cdrpnm.com",
	"idrfwa.com",
	"ktrubn.com",
	"xohmsv.com",
	"mmddcs.com",
	"mlmgvj.com",
	"myxcwb.com",
	"rrlbbu.com",
	"abifcu.com",
	"uarnen.com",
	"utvepr.com",
	"hvriwm.com",
	"ktoobi.com",
	"pkucoi.com",
	"enszeo.com",
	"boerwx.com",
	"oftmjp.com",
	"conpid.com",
	"xsixnx.com",
	"acbdut.com",
	"oipdfz.com",
	"cceope.com",
	"shyuyj.com",
	"flddpw.com",
	"hmdtxy.com",
	"lsfqfe.com",
	"ynmpsm.com",
	"kbkkbn.com",
	"xrerap.com",
	"dhhhkr.com",
	"zdbnpt.com",
	"ttxvat.com",
	"rkrnjg.com",
	"xkanxi.com",
	"nbcmqi.com",
	"mmhner.com",
	"elunlf.com",
	"bjupxh.com",
	"loosax.com",
	"fliwby.com",
	"kjelwq.com",
	"nlcgov.com",
	"jjxavu.com",
	"gpalyx.com",
	"ckycee.com",
	"msngsw.com",
}

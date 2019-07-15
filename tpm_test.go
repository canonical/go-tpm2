package tpm2

import (
	"flag"
	"testing"
)

var tpmPath = flag.String("tpm-path", "", "")

func openTPMForTesting(t *testing.T) TPM {
	if *tpmPath == "" {
		t.SkipNow()
	}
	tpm, err := OpenTPM(*tpmPath)
	if err != nil {
		t.Fatalf("Failed to open the TPM device: %v", err)
	}
	return tpm
}

func flushContext(t *testing.T, tpm TPM, handle Resource) {
	if err := tpm.FlushContext(handle); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}
}

package fetcher_test

import (
	"testing"

	"github.com/gamesapeca/gha-oidc-auditor/pkg/fetcher"
)

func TestScanLocalPath_Directory(t *testing.T) {
	wfs, err := fetcher.ScanLocalPath("../../testdata/vulnerable")
	if err != nil {
		t.Fatalf("failed to scan local directory: %v", err)
	}

	if len(wfs) < 5 {
		t.Errorf("expected at least 5 workflows in testdata/vulnerable, got: %d", len(wfs))
	}
}

func TestScanLocalPath_SingleFile(t *testing.T) {
	wfs, err := fetcher.ScanLocalPath("../../testdata/safe/sha_pinned_oidc.yml")
	if err != nil {
		t.Fatalf("failed to scan single file: %v", err)
	}

	if len(wfs) != 1 {
		t.Fatalf("expected 1 workflow, got: %d", len(wfs))
	}

	if wfs[0].Name != "Safe SHA Pinned OIDC" {
		t.Errorf("incorrect workflow name: %s", wfs[0].Name)
	}
}

func TestScanLocalPath_NonExistent(t *testing.T) {
	_, err := fetcher.ScanLocalPath("../../testdata/non_existent_dir")
	if err == nil {
		t.Errorf("expected error for non-existent path, got nil")
	}
}

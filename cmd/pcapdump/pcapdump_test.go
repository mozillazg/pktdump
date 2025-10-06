package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbsoluteSeqFlag(t *testing.T) {
	demo := filepath.Join("demo.pcap")

	cmd := exec.Command("go", "run", ".", "--absolute-seq", demo)
	cmd.Dir = "."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("pcapdump --absolute-seq failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 lines of output, got %d", len(lines))
	}

	fourth := lines[3]
	if !strings.Contains(fourth, "seq 4071596915:4071598264") {
		t.Fatalf("expected absolute sequence range in fourth line, got %q", fourth)
	}
	if strings.Contains(fourth, "seq 1:1350") {
		t.Fatalf("absolute mode should not print relative sequence numbers, got %q", fourth)
	}
}

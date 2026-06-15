package db

import "testing"

func TestMigrationChecksumIsStableAndContentSensitive(t *testing.T) {
	first := migrationChecksum([]byte("SELECT 1;\n"))
	second := migrationChecksum([]byte("SELECT 1;\n"))
	changed := migrationChecksum([]byte("SELECT 2;\n"))

	if first != second {
		t.Fatal("expected identical migration contents to have the same checksum")
	}
	if first == changed {
		t.Fatal("expected changed migration contents to have a different checksum")
	}
}

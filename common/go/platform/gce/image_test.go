package gce

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestConvertToGCETarGz(t *testing.T) {
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "test-disk.img")
	srcData := bytes.Repeat([]byte("PANCAKE!"), 1024) // 8 KiB
	if err := os.WriteFile(srcPath, srcData, 0o644); err != nil {
		t.Fatal(err)
	}

	tarPath, err := ConvertToGCETarGz(srcPath, tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("read tar header: %v", err)
	}
	if hdr.Name != "disk.raw" {
		t.Errorf("tar entry name = %q, want disk.raw", hdr.Name)
	}
	if hdr.Size != int64(len(srcData)) {
		t.Errorf("tar entry size = %d, want %d", hdr.Size, len(srcData))
	}

	contents, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, srcData) {
		t.Error("tar entry contents differ from source")
	}

	if _, err := tr.Next(); err != io.EOF {
		t.Errorf("expected only one entry in tar, got more (err=%v)", err)
	}
}

func TestParseGSPath(t *testing.T) {
	cases := []struct {
		in, defaultName     string
		wantBucket, wantObj string
	}{
		{"gs://my-bucket/foo.tar.gz", "x", "my-bucket", "foo.tar.gz"},
		{"my-bucket/foo.tar.gz", "x", "my-bucket", "foo.tar.gz"},
		{"my-bucket", "default.bin", "my-bucket", "default.bin"},
		{"gs://my-bucket", "default.bin", "my-bucket", "default.bin"},
		{"my-bucket/path/to/file", "x", "my-bucket", "path/to/file"},
	}
	for _, c := range cases {
		gotB, gotO, err := parseGSPath(c.in, c.defaultName)
		if err != nil {
			t.Errorf("parseGSPath(%q): unexpected error %v", c.in, err)
			continue
		}
		if gotB != c.wantBucket || gotO != c.wantObj {
			t.Errorf("parseGSPath(%q) = (%q, %q), want (%q, %q)",
				c.in, gotB, gotO, c.wantBucket, c.wantObj)
		}
	}
}

func TestHTTPSURIForGSPath(t *testing.T) {
	got := httpsURIForGSPath("gs://my-bucket/foo.tar.gz")
	want := "https://storage.googleapis.com/my-bucket/foo.tar.gz"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

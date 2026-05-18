package gcpcas

import "testing"

func TestSanitizeCertID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"pancake-demo", "pancake-demo"},
		{"PANCAKE-DEMO", "pancake-demo"},
		{"vm.example.com", "vm-example-com"},
		{"vm_42", "vm-42"},
		{"!@#$%", "pancake-vm"}, // nothing usable → default
		{"", "pancake-vm"},
		// length cap (50 chars)
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXX",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, c := range cases {
		got := sanitizeCertID(c.in)
		if got != c.want {
			t.Errorf("sanitizeCertID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNew(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("New(\"\") should error")
	}
	i, err := New("projects/p/locations/l/caPools/x")
	if err != nil {
		t.Fatal(err)
	}
	if i.Name() != "gcp-cas" {
		t.Errorf("Name() = %q, want gcp-cas", i.Name())
	}
	if i.Lifetime == 0 {
		t.Error("Lifetime should default non-zero")
	}
}

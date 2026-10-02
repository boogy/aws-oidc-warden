package config

import "testing"

func TestSplitConfigPath(t *testing.T) {
	tmp := t.TempDir()
	tests := []struct {
		name     string
		in       string
		wantDir  string
		wantName string
	}{
		{"example-config.yaml", "./example-config.yaml", ".", "example-config"},
		{"absolute yml", "/abs/x.yml", "/abs", "x"},
		{"json relative", "conf.json", ".", "conf"},
		{"existing directory", tmp, tmp, ""},
		{"absent no extension", "/etc/warden", "/etc/warden", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, name := SplitConfigPath(tt.in)
			if dir != tt.wantDir || name != tt.wantName {
				t.Errorf("SplitConfigPath(%q) = (%q, %q), want (%q, %q)", tt.in, dir, name, tt.wantDir, tt.wantName)
			}
		})
	}
}

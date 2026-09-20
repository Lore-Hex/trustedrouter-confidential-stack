package main

import (
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
)

func TestStandardLibraryOnly(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-json", "./...")
	cmd.Dir = "../.."
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for {
		var p struct {
			ImportPath string
			Standard   bool
		}
		err := decoder.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !p.Standard && p.ImportPath != "github.com/Lore-Hex/trustedrouter-confidential-stack" && !strings.HasPrefix(p.ImportPath, "github.com/Lore-Hex/trustedrouter-confidential-stack/") {
			t.Fatalf("non-stdlib dependency: %s", p.ImportPath)
		}
	}
}
func TestShimEnvironment(t *testing.T) {
	t.Setenv("TRCS_LISTEN", ":9443")
	t.Setenv("TRCS_TEE", "none")
	t.Setenv("TRCS_TLS_SAN", "a,b")
	t.Setenv("TRCS_REQUIRE_TEE", "true")
	t.Setenv("TRCS_MAX_REQUEST_BYTES", "100")
	c, err := shimFlags([]string{"--listen=:8443", "--tls-san=c", "--tls-san=d"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.TEE != "none" || !c.RequireTEE || c.MaxRequestBytes != 100 || strings.Join(c.TLSSANs, ",") != "c,d" {
		t.Fatalf("%+v", c)
	}
}
func TestBadEnvironment(t *testing.T) {
	t.Setenv("TRCS_REQUIRE_TEE", "invalid")
	if _, err := shimFlags(nil); err == nil {
		t.Fatal("invalid boolean accepted")
	}
}

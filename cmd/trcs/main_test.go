package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/shim"
)

func TestShutdownDrainsActiveTLSResponse(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "drained", true: "deadline"}[deadline], func(t *testing.T) {
			c := shim.DefaultConfig()
			c.TEE, c.EvidenceSource, c.ListenerAudit = "none", "none", "off"
			c.TLSSANs = []string{"127.0.0.1"}
			server, err := shim.New(context.Background(), c, nil, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			defer server.HTTP.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			started, release := make(chan struct{}), make(chan struct{})
			server.HTTP.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "first ")
				w.(http.Flusher).Flush()
				close(started)
				select {
				case <-release:
					_, _ = io.WriteString(w, "last")
				case <-r.Context().Done():
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			grace := 5 * time.Second
			if deadline {
				grace = 20 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() { done <- serveUntilStopped(ctx, server, listener, grace) }()
			roots := x509.NewCertPool()
			cert, err := x509.ParseCertificate(server.HTTP.TLSConfig.Certificates[0].Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			roots.AddCert(cert)
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
			response, err := client.Get("https://" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			<-started
			cancel()
			if deadline {
				select {
				case err := <-done:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("shutdown deadline reported success: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("shutdown deadline not enforced")
				}
				if _, err := io.ReadAll(response.Body); err == nil {
					t.Fatal("forced closure was not visible to client")
				}
				return
			}
			select {
			case err := <-done:
				close(release)
				t.Fatalf("exited before response drained: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "first last" {
				t.Fatalf("response interrupted: %v", err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server remained alive after draining")
			}
		})
	}
}

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
	t.Setenv("TRCS_MAX_INFLIGHT", "7")
	c, err := shimFlags([]string{"--listen=:8443", "--tls-san=c", "--tls-san=d"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.TEE != "none" || !c.RequireTEE || c.MaxRequestBytes != 100 || c.MaxInflight != 7 || strings.Join(c.TLSSANs, ",") != "c,d" {
		t.Fatalf("%+v", c)
	}
}

func TestShimInflightCLIOverridesEnvironment(t *testing.T) {
	t.Setenv("TRCS_MAX_INFLIGHT", "7")
	c, err := shimFlags([]string{"--max-inflight=3"})
	if err != nil || c.MaxInflight != 3 {
		t.Fatalf("max-inflight=%d err=%v", c.MaxInflight, err)
	}
}
func TestBadEnvironment(t *testing.T) {
	t.Setenv("TRCS_REQUIRE_TEE", "invalid")
	if _, err := shimFlags(nil); err == nil {
		t.Fatal("invalid boolean accepted")
	}
}

func TestShutdownGraceConfiguration(t *testing.T) {
	c, err := shimFlags(nil)
	if err != nil || c.ShutdownGrace != 130*time.Second {
		t.Fatalf("default grace=%v err=%v", c.ShutdownGrace, err)
	}
	t.Setenv("TRCS_SHUTDOWN_GRACE", "910s")
	c, err = shimFlags(nil)
	if err != nil || c.ShutdownGrace != 910*time.Second {
		t.Fatalf("environment grace=%v err=%v", c.ShutdownGrace, err)
	}
	c, err = shimFlags([]string{"--shutdown-grace=20m"})
	if err != nil || c.ShutdownGrace != 20*time.Minute {
		t.Fatalf("CLI grace=%v err=%v", c.ShutdownGrace, err)
	}
	t.Setenv("TRCS_SHUTDOWN_GRACE", "not-a-duration")
	if _, err = shimFlags(nil); err == nil {
		t.Fatal("invalid grace environment accepted")
	}
}

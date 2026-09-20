package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/checkendpoint"
	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/manifestlint"
	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/preflight"
	"github.com/Lore-Hex/trustedrouter-confidential-stack/internal/shim"
)

var version = "0.1.0"

type repeated struct {
	values *[]string
	set    bool
}

func (r *repeated) String() string { return strings.Join(*r.values, ",") }
func (r *repeated) Set(s string) error {
	if !r.set {
		*r.values = nil
		r.set = true
	}
	*r.values = append(*r.values, s)
	return nil
}

func shimFlags(args []string) (shim.Config, error) {
	c := shim.DefaultConfig()
	c.Workload.StackVersion = version
	f := flag.NewFlagSet("shim", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.Listen, "listen", c.Listen, "HTTPS listen address")
	f.StringVar(&c.Upstream, "upstream", c.Upstream, "inference HTTP(S) origin")
	f.BoolVar(&c.AllowRemoteUpstream, "allow-remote-upstream", false, "allow non-loopback inference")
	f.StringVar(&c.TEE, "tee", c.TEE, "auto|none|sev-snp|tdx")
	f.StringVar(&c.EvidenceSource, "evidence-source", c.EvidenceSource, "auto|none|configfs-tsm|coco-aa|dstack (dstack is experimental; coco-aa and dstack need an explicit --tee)")
	f.StringVar(&c.TSMPath, "tsm-path", c.TSMPath, "configfs TSM report directory")
	f.StringVar(&c.CocoAAURL, "coco-aa-url", c.CocoAAURL, "Confidential Containers guest attestation agent origin; loopback only")
	f.StringVar(&c.DstackSocket, "dstack-socket", c.DstackSocket, "dstack guest agent unix socket")
	f.StringVar(&c.ListenerAudit, "listener-audit", c.ListenerAudit, "auto|enforce|warn|off: refuse to serve while another process listens on a non-loopback address (auto enforces whenever a TEE is in use)")
	f.StringVar(&c.ProcNetDir, "proc-net-dir", c.ProcNetDir, "directory holding the tcp and tcp6 socket tables")
	f.BoolVar(&c.RequireTEE, "require-tee", false, "require a successful CPU evidence self-test")
	f.StringVar(&c.TLSCert, "tls-cert", "", "operator certificate (tee=none only)")
	f.StringVar(&c.TLSKey, "tls-key", "", "operator key (tee=none only)")
	sans := &repeated{values: &c.TLSSANs}
	prefixes := &repeated{values: &c.AllowPathPrefixes}
	f.Var(sans, "tls-san", "repeatable certificate DNS name or IP; env accepts comma-separated values")
	f.Var(prefixes, "allow-path-prefix", "repeatable proxy path prefix; env accepts comma-separated values")
	f.StringVar(&c.GPUEvidenceCommand, "gpu-evidence-cmd", "", "executable and quoted arguments; no shell expansion")
	f.StringVar(&c.Workload.Model, "model", "", "untrusted workload hint")
	f.StringVar(&c.Workload.ModelRevision, "model-revision", "", "untrusted workload hint")
	f.StringVar(&c.Workload.EngineImage, "engine-image", "", "untrusted workload hint")
	f.Float64Var(&c.AttestationRate, "attestation-rate", c.AttestationRate, "requests per second; burst 5")
	f.Int64Var(&c.MaxRequestBytes, "max-request-bytes", c.MaxRequestBytes, "maximum proxied body size")
	var envErr error
	f.VisitAll(func(option *flag.Flag) {
		value, ok := os.LookupEnv("TRCS_" + strings.ToUpper(strings.ReplaceAll(option.Name, "-", "_")))
		if !ok {
			return
		}
		values := []string{value}
		if option.Name == "tls-san" || option.Name == "allow-path-prefix" {
			values = strings.Split(value, ",")
		}
		for _, v := range values {
			if err := option.Value.Set(v); err != nil {
				envErr = fmt.Errorf("invalid environment value for %s", option.Name)
			}
		}
	})
	if envErr != nil {
		return c, envErr
	}
	sans.set = false
	prefixes.set = false // CLI lists replace environment lists.
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 {
		return c, fmt.Errorf("unexpected shim positional arguments")
	}
	return c, nil
}
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: trcs shim|preflight|check-endpoint|lint-manifests|version")
		return 1
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(os.Stdout, version)
		return 0
	case "shim":
		c, err := shimFlags(args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		server, err := shim.New(ctx, c, nil, os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "shim startup:", err)
			return 1
		}
		listener, err := net.Listen("tcp", c.Listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen failed")
			return 1
		}
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdown)
			case <-done:
			}
		}()
		if err = server.Serve(listener); err != nil && !shim.IsClosed(err) {
			fmt.Fprintln(os.Stderr, "HTTPS server failed")
			return 1
		}
		return 0
	case "preflight":
		f := flag.NewFlagSet("preflight", flag.ContinueOnError)
		root := f.String("root", "/", "filesystem root")
		asJSON := f.Bool("json", false, "JSON output")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 {
			return 2
		}
		return preflight.Run(context.Background(), *root, *asJSON, nil, os.Stdout, os.Stderr)
	case "check-endpoint":
		// Accept both documented forms: flags before or after the URL.
		f := flag.NewFlagSet("check-endpoint", flag.ContinueOnError)
		expect := f.String("expect-tee", "any", "none|sev-snp|tdx|any")
		asJSON := f.Bool("json", false, "JSON output")
		rest := args[1:]
		endpoint := ""
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			endpoint = rest[0]
			rest = rest[1:]
		}
		if f.Parse(rest) != nil {
			return 1
		}
		if endpoint == "" && f.NArg() == 1 {
			endpoint = f.Arg(0)
		} else if f.NArg() != 0 {
			return 1
		}
		return checkendpoint.Run(context.Background(), endpoint, *expect, *asJSON, os.Stdout, os.Stderr)
	case "lint-manifests":
		f := flag.NewFlagSet("lint-manifests", flag.ContinueOnError)
		mode := f.String("mode", "standard", "standard|coco")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 {
			return 1
		}
		return manifestlint.Run(os.Stdin, os.Stdout, *mode)
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand")
		return 1
	}
}
func main() { os.Exit(run(os.Args[1:])) }

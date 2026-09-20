// trcs-helm-test is a shell-free Helm hook for the distroless image.
// It does not change check-endpoint's exit-code contract for users.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func hookCode(mode string, code int) int {
	if mode == "coco" && code == 3 {
		return 0
	}
	return code
}
func main() {
	if len(os.Args) < 3 || (os.Args[1] != "none" && os.Args[1] != "coco") {
		fmt.Fprintln(os.Stderr, "usage: trcs-helm-test none|coco <check-endpoint args>")
		os.Exit(1)
	}
	cmd := exec.Command("/trcs", append([]string{"check-endpoint"}, os.Args[2:]...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(hookCode(os.Args[1], exit.ExitCode()))
		}
		fmt.Fprintln(os.Stderr, "could not execute trcs check-endpoint")
		os.Exit(1)
	}
}

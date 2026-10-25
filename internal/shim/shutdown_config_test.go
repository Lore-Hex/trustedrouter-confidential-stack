package shim

import (
	"testing"
	"time"
)

func TestShutdownGraceBounds(t *testing.T) {
	for _, grace := range []time.Duration{-time.Second, 0, time.Second - 1, time.Hour + 1} {
		c := DefaultConfig()
		c.ShutdownGrace = grace
		if _, err := c.validate(); err == nil {
			t.Errorf("invalid shutdown grace %v accepted", grace)
		}
	}
	for _, grace := range []time.Duration{time.Second, 130 * time.Second, 910 * time.Second, time.Hour} {
		c := DefaultConfig()
		c.ShutdownGrace = grace
		if _, err := c.validate(); err != nil {
			t.Errorf("valid shutdown grace %v rejected: %v", grace, err)
		}
	}
}

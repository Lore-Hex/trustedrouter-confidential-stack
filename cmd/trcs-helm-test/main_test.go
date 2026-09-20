package main

import "testing"

func TestHookExitContract(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		in, want int
	}{{"none", 0, 0}, {"none", 1, 1}, {"none", 3, 3}, {"coco", 0, 0}, {"coco", 1, 1}, {"coco", 3, 0}} {
		if got := hookCode(tc.mode, tc.in); got != tc.want {
			t.Fatalf("%s/%d: got %d want %d", tc.mode, tc.in, got, tc.want)
		}
	}
}

//go:build !linux

package main

import "errors"

var errUnsupportedPlatform = errors.New("unsupported platform")

func collectHostMetrics(_ string) (map[string]any, error) {
	return map[string]any{"unsupported_platform": true}, errUnsupportedPlatform
}

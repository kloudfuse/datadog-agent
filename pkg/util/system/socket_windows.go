// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package system

import (
	"errors"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

// On Windows, socket does not exist, usually replaced by named pipe
func CheckSocketAvailable(path string, timeout time.Duration) bool {
	if !checkSocketExists(path) {
		return false
	}

	_, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return false
	}

	return true
}

func checkSocketExists(path string) bool {
	f, err := os.Stat(path)
	if err != nil {
		return false
	}

	// On Windows there's not easy to check if a path is a named pipe
	return true
}

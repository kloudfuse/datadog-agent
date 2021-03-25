// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build !windows

package system

import (
	"errors"
	"net"
	"os"
	"time"
)

// CheckSocketAvailable returns if a socket at path is available
func CheckSocketAvailable(path string, timeout time.Duration) bool {
	if !checkSocketExists(path) {
		return false
	}

	// Assuming socket file exists (bind() done)
	// -> but we don't have permission: permission denied
	// -> but no process associated to socket anymore: connection refused
	// -> but process did not call listen(): connection refused
	// -> but process does not call accept(): no error
	// We'll consider socket available in all cases except if permission is denied
	// as if a path exists and we do have access, it's likely that a process will re-use it later.
	_, err := net.DialTimeout("unix", path, timeout)
	if err != nil && errors.Is(err, os.ErrPermission) {
		return false
	}

	return true
}

func checkSocketExists(path string) bool {
	f, err := os.Stat(path)
	if err != nil {
		return false
	}

	if f.Mode()&os.ModeSocket != 0 {
		return true
	}

	return false
}

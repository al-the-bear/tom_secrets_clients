// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package tsm

import (
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Endpoints are the runtime directory and its endpoint files (protocol.md
// section 3): the Unix domain sockets on Linux and macOS, the port and
// token files on Windows; the names a platform does not use are "".
type Endpoints struct {
	Directory       string
	ClientSocket    string
	AdminSocket     string
	ClientPortFile  string
	ClientTokenFile string
	AdminPortFile   string
}

// CurrentOperatingSystem is "linux", "macos" or "windows", as the rules name
// this process's.
func CurrentOperatingSystem() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin", "ios":
		return "macos"
	}
	return "linux"
}

func stripSeparators(path string, windows bool) string {
	end := len(path)
	for end > 0 && (path[end-1] == '/' || (windows && path[end-1] == '\\')) {
		end--
	}
	if end == 0 {
		return path
	}
	return path[:end]
}

// Discover finds the service (3.1) for operatingSystem (others than "macos"
// and "windows" are treated as "linux"), environment and the numeric user
// id (uid is called only for the /tmp/tsm-<uid> fallback). ok is false when
// no runtime directory can be named (Windows without LOCALAPPDATA and
// USERPROFILE): the service is not running.
func Discover(operatingSystem string, environment map[string]string, uid func() int) (endpoints Endpoints, ok bool) {
	windows := operatingSystem == "windows"
	var directory string
	if override := environment["TSM_RUNTIME_DIR"]; override != "" {
		directory = stripSeparators(override, windows)
	} else if windows {
		local, profile := environment["LOCALAPPDATA"], environment["USERPROFILE"]
		var base string
		switch {
		case local != "":
			base = stripSeparators(local, true)
		case profile != "":
			base = stripSeparators(profile, true) + `\AppData\Local`
		default:
			return Endpoints{}, false
		}
		directory = base + `\TomSecretsManager\run`
	} else {
		variable := "XDG_RUNTIME_DIR"
		if operatingSystem == "macos" {
			variable = "TMPDIR"
		}
		if value := environment[variable]; strings.HasPrefix(value, "/") {
			directory = stripSeparators(value, false) + "/tsm"
		} else {
			directory = "/tmp/tsm-" + strconv.Itoa(uid())
		}
	}
	if windows {
		return Endpoints{
			Directory:       directory,
			ClientPortFile:  directory + `\client.port`,
			ClientTokenFile: directory + `\client.token`,
			AdminPortFile:   directory + `\admin.port`,
		}, true
	}
	return Endpoints{
		Directory:    directory,
		ClientSocket: directory + "/client.sock",
		AdminSocket:  directory + "/admin.sock",
	}, true
}

// processEnvironment is this process's environment as a map.
func processEnvironment() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func stripLineEnd(text string) string {
	if strings.HasSuffix(text, "\r\n") {
		return text[:len(text)-2]
	}
	return strings.TrimSuffix(text, "\n")
}

var portPattern = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

// ReadPortFile is the port a port file's text names (decimal 1-65535, no
// sign or leading zero, at most one trailing LF or CR LF); ok is false
// when it is unreadable.
func ReadPortFile(text string) (port int, ok bool) {
	body := stripLineEnd(text)
	if !portPattern.MatchString(body) {
		return 0, false
	}
	port, _ = strconv.Atoi(body)
	return port, port <= 65535
}

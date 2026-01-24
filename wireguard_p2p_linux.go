//go:build linux
// +build linux

/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

func writeWireGuardInterface(_ string, config wireguardConfig) error {
	slog.Debug("Writing WireGuard interface configuration", "interface", config.Interface)
	return os.WriteFile(filepath.Join("/etc/wireguard", config.Interface+".conf"), []byte(config.String()), 0600)
}

func deleteWireGuardInterface(interfaceName, _ string) error {
	slog.Debug("Deleting WireGuard interface configuration", "interface", interfaceName)
	return os.Remove(filepath.Join("/etc/wireguard", interfaceName+".conf"))
}

func installWireguardInterface(interfaceName, _ string) error {
	slog.Debug("Installing WireGuard interface", "interface", interfaceName)
	cmd := exec.Command("wg-quick", "up", interfaceName)
	cmd.Stdout = slogWriter{level: slog.LevelInfo}
	cmd.Stderr = slogWriter{level: slog.LevelError}
	return cmd.Run()
}

func uninstallWireguardInterface(interfaceName string) error {
	slog.Debug("Uninstalling WireGuard interface", "interface", interfaceName)
	cmd := exec.Command("wg-quick", "down", interfaceName)
	cmd.Stdout = slogWriter{level: slog.LevelInfo}
	cmd.Stderr = slogWriter{level: slog.LevelError}
	return cmd.Run()
}

func syncWireguardInterface(interfaceName, _ string) error {
	slog.Debug("Syncing WireGuard interface configuration", "interface", interfaceName)
	cmd := exec.Command("wg", "syncconf", interfaceName, filepath.Join("/etc/wireguard", interfaceName+".conf"))
	cmd.Stdout = slogWriter{level: slog.LevelInfo}
	cmd.Stderr = slogWriter{level: slog.LevelError}
	return cmd.Run()
}

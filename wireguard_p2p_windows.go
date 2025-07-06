//go:build windows
// +build windows

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
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func writeWireGuardInterface(configPath string, config wireguardConfig) error {
	slog.Debug("Writing WireGuard interface configuration", "interface", config.Interface, "configPath", configPath)
	return os.WriteFile(filepath.Join(configPath, config.Interface+".conf"), []byte(config.String()), 0600)
}

func deleteWireGuardInterface(interfaceName, configPath string) error {
	slog.Debug("Deleting WireGuard interface configuration", "interface", interfaceName, "configPath", configPath)
	return os.Remove(filepath.Join(configPath, interfaceName+".conf"))
}

func installWireguardInterface(interfaceName, configPath string) error {
	slog.Debug("Installing WireGuard interface", "interface", interfaceName, "configPath", configPath)
	if strings.HasSuffix(configPath, ".conf") {
		return errors.New("Config file must be a .conf file")
	}

	cmd := exec.Command("wireguard", "/installtunnelservice", filepath.Join(configPath, interfaceName+".conf"))
	cmd.Stdout = slogWriter{level: slog.LevelInfo}
	cmd.Stderr = slogWriter{level: slog.LevelError}
	return cmd.Run()
}

func uninstallWireguardInterface(interfaceName string) error {
	slog.Debug("Uninstalling WireGuard interface", "interface", interfaceName)
	cmd := exec.Command("wireguard", "/uninstalltunnelservice", interfaceName)
	cmd.Stdout = slogWriter{level: slog.LevelInfo}
	cmd.Stderr = slogWriter{level: slog.LevelError}
	return cmd.Run()
}

func syncWireguardInterface(interfaceName, configPath string) error {
	if err := uninstallWireguardInterface(interfaceName); err != nil {
		return err
	}

	for i := 0; ; i++ {
		err := installWireguardInterface(interfaceName, configPath)
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
		if i >= 10 {
			slog.Error("Failed to install WireGuard interface after multiple attempts", "interface", interfaceName, "error", err)
			return err
		}
	}
}

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
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func writeWireGuardInterface(_ string, config wireguardConfig) error {
	return os.WriteFile(filepath.Join("/etc/wireguard", config.Interface+".conf"), []byte(config.String()), 0600)
}

func deleteWireGuardInterface(interfaceName, _ string) error {
	return os.Remove(filepath.Join("/etc/wireguard", interfaceName+".conf"))
}

func installWireguardInterface(interfaceName, _ string) error {
	return exec.Command("wg-quick", "up", interfaceName).Run()
}

func uninstallWireguardInterface(interfaceName string) error {
	return exec.Command("wg-quick", "down", interfaceName).Run()
}

func syncWireguardInterface(interfaceName, _ string) error {
	if err := uninstallWireguardInterface(interfaceName); err != nil {
		return err
	}
	for i := 0; ; i++ {
		err := installWireguardInterface(interfaceName, "")
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
		if i >= 10 {
			return err
		}
	}
}

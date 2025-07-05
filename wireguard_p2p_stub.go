//go:build !windows && !linux
// +build !windows,!linux

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
)

func writeWireGuardInterface(_ string, _ wireguardConfig) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func deleteWireGuardInterface(interfaceName, configPath string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func installWireguardInterface(_, _ string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func uninstallWireguardInterface(_ string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func syncWireguardInterface(_, _ string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

package remotecontrol

import (
	"bytes"
	"golang.org/x/sys/windows/registry"
	"os/exec"
	"strings"
)

func IsRunning(processKeywords string) bool {
	cmd := exec.Command("tasklist")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return false
	}
	return strings.Contains(out.String(), processKeywords)
}

func IsInstalled(appKeywords string) bool {
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, appKeywords, registry.READ)
	if err != nil {
		return false
	}
	return true
}

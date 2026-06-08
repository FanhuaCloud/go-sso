package version

import "strings"

var Version = "dev"

func Current() string {
	value := strings.TrimSpace(Version)
	if value == "" {
		return "dev"
	}
	return value
}

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type IPFlag string
type FileFlag string

func (f *IPFlag) UnmarshalFlag(value string) error {
	parsedIP := net.ParseIP(value)
	if parsedIP == nil {
		return fmt.Errorf("Invalid IP: '%s'", value)
	}

	*f = IPFlag(parsedIP.String())

	return nil
}

func (f *FileFlag) UnmarshalFlag(value string) error {
	stat, err := os.Stat(value)
	if err != nil {
		return err
	}

	if stat.IsDir() {
		return fmt.Errorf("Path '%s' is a directory, not a file", value)
	}

	abs, err := filepath.Abs(value)
	if err != nil {
		return err
	}

	*f = FileFlag(abs)

	return nil
}

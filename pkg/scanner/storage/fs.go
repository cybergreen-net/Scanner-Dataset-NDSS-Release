package storage

import (
	"os"
)

func CreateDirectoryIfNotExists(directoryPath string) error {
	if _, err := os.Stat(directoryPath); os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, os.ModePerm)
		if err != nil {
			// Failed to create the necessary directory, return this to the client.
			return err
		}
	}
	return nil
}

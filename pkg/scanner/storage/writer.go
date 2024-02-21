package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
	"strings"
)

type FileWriteInformation struct {
	DirectoryPath string
	Filename      string
	FileExtension string
}

func generateRandomFileName() string {
	b := make([]byte, RandomFileNameSize)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	// Hex encode to string
	return hex.EncodeToString(b)
}

func NewFileWriteInformationRequest(dirPath string, filename string, prefix string, extension string) FileWriteInformation {
	filename = strings.TrimSpace(filename)
	if len(strings.TrimSpace(dirPath)) == 0 {
		panic("Directory path for saving results cannot be empty. Please retry with modifications to --out-dir")
	}
	if len(filename) == 0 {
		filename = fmt.Sprintf("%v%v", prefix, generateRandomFileName())
	}
	f := FileWriteInformation{
		DirectoryPath: dirPath,
		Filename:      filename,
		FileExtension: extension,
	}
	return f
}

func (f *FileWriteInformation) getFilePath() string {
	fileNameWithExtension := fmt.Sprintf("%s.%s", f.Filename, f.FileExtension)
	outFilePath := filepath.Join(f.DirectoryPath, fileNameWithExtension)
	return outFilePath
}

func (f *FileWriteInformation) WriteDataToFile(data []byte) error {
	err := CreateDirectoryIfNotExists(f.DirectoryPath)
	if err != nil {
		return err
	}
	outFilePath := f.getFilePath()
	fmt.Printf("Writing output to [%v]\n", outFilePath)
	return os.WriteFile(outFilePath, data, 0644)
}

func GenerateOutputAndTeardown(context *cli.Context, serializableData interface{}) error {
	outDirectory := context.String("out-dir")
	outFile := context.String("out-file")
	shouldWriteToDisk := context.Bool("json")
	jsonPretty := context.Bool("pretty")

	var filePrefix string
	switch context.Command.Name {
	case "tls":
		filePrefix = TLSResultFilePrefix
		break
	case "mail":
		filePrefix = EmailResultFilePrefix
		break
	case "dns":
		filePrefix = DNSResultFilePrefix
		break
	}

	var data []byte
	switch jsonPretty {
	case true:
		data, _ = json.MarshalIndent(serializableData, "", "\t")
		break
	case false:
		data, _ = json.Marshal(serializableData)
		break
	}

	if shouldWriteToDisk {
		outFile = strings.TrimSpace(outFile)
		writeRequest := NewFileWriteInformationRequest(outDirectory, outFile, filePrefix, ExtensionJSON)
		err := writeRequest.WriteDataToFile(data)
		return err
	} else {
		fmt.Println(string(data))
	}
	return nil
}

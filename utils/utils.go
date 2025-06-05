package utils

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// ReadLines reads all lines from the file at the given path and returns them as a slice of strings.
// It returns an error if the file cannot be read.
// This utility is used throughout the repository to load configuration or data files line by line.
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// CreateFile creates a file with the specified filename inside the given filepath.
// If the directory does not exist, it will be created.
// Returns a pointer to the created file and an error if the operation fails.
func CreateFile(filepath string, filename string) (fo *os.File, err error) {
	InitFolder(filepath)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return os.Create(filepath + "/" + filename)
}

// InitFolder creates a folder with the specified name if it does not already exist.
// Returns an error if the directory cannot be created or accessed.
func InitFolder(folder_name string) error {
	var err error
	if _, err = os.Stat(folder_name); os.IsNotExist(err) {
		err = os.Mkdir(folder_name, os.ModePerm)
	}
	return err
}

// ExtractTarGz extracts the contents of a .tar.gz stream to the current directory.
// Returns the name of the last directory extracted, or an error if extraction fails.
func ExtractTarGz(gzipStream io.Reader) string {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		log.Fatal("ExtractTarGz: NewReader failed")
	}

	tarReader := tar.NewReader(uncompressedStream)
	folderName := ""
	for true {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatalf("ExtractTarGz: Next() failed: %s", err.Error())
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(header.Name); os.IsNotExist(err) {
				if err := os.Mkdir(header.Name, 0755); err != nil {
					log.Fatalf("ExtractTarGz: Mkdir() failed: %s", err.Error())
				}
			}
			folderName = header.Name
		case tar.TypeReg:
			outFile, err := os.Create(header.Name)
			if err != nil {
				log.Fatalf("ExtractTarGz: Create() failed: %s", err.Error())
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				log.Fatalf("ExtractTarGz: Copy() failed: %s", err.Error())
			}
			err = outFile.Close()
			if err != nil {
				log.Fatalf("ExtractTarGz: ", err.Error())
			}

		default:
			log.Fatalf(
				"ExtractTarGz: uknown type: %s in %s",
				header.Typeflag,
				header.Name)
		}

	}
	return folderName
}

// RemoveFolderContents deletes all files and subdirectories within the specified directory,
// but does not remove the directory itself. Returns an error if any operation fails.
func RemoveFolderContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

/*
   GoLang: os.Rename() give error "invalid cross-device link" for Docker container with Volumes.
   MoveFile(source, destination) will work moving file between folders
	https://gist.github.com/var23rav/23ae5d0d4d830aff886c3c970b8f6c6b
*/

// MoveFile moves a file from sourcePath to destPath by copying its contents and then deleting the original file.
// This is useful when os.Rename fails due to "invalid cross-device link" errors, such as with Docker volumes.
// Returns an error if the source file cannot be opened, the destination file cannot be created, the copy fails, or the original file cannot be deleted.
func MoveFile(sourcePath, destPath string) error {
	inputFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("Couldn't open source file: %s", err)
	}
	outputFile, err := os.Create(destPath)
	if err != nil {
		inputFile.Close()
		return fmt.Errorf("Couldn't open dest file: %s", err)
	}
	defer outputFile.Close()
	_, err = io.Copy(outputFile, inputFile)
	inputFile.Close()
	if err != nil {
		return fmt.Errorf("Writing to output file failed: %s", err)
	}
	// The copy was successful, so now delete the original file
	err = os.Remove(sourcePath)
	if err != nil {
		return fmt.Errorf("Failed removing original file: %s", err)
	}
	return nil
}

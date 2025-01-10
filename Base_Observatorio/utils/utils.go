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

//Auxiliar function to read lines from a file path. return a string array with all the lines in the file and an error if fails ->(lines, error)
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

//Creates a file given a path and a name for the file
func CreateFile(filepath string, filename string) (fo *os.File, err error) {
	InitFolder(filepath)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return os.Create(filepath + "/" + filename)
}

//Creates (if dont exists) a folder given a name
func InitFolder(folder_name string) error {
	var err error
	if _, err = os.Stat(folder_name); os.IsNotExist(err) {
		err = os.Mkdir(folder_name, os.ModePerm)
	}
	return err
}

func ExtractTarGz(gzipStream io.Reader) (string){
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		log.Fatal("ExtractTarGz: NewReader failed")
	}

	tarReader := tar.NewReader(uncompressedStream)
	folderName:= ""
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
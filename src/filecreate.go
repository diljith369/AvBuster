package main

import (
	"fmt"
	"os"
)

var owntemplate string

func init() {
	owntemplate = `<!DOCTYPE html>
	<html>
	<body>
	<form action="" method="post" id="cmdform" name="cmdform">
		<input type="text" class="form-control" name="cmd" id="cmd" value= {{.Command}}>
	</form>
	</body>
	</html>`
}

func main() {

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

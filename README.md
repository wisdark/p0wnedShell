# p0wnedShell
PowerShell Runspace Post Exploitation Toolkit 

### Author: Cn33liz

License: BSD 3-Clause

### What is it:

p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET). It has a lot of offensive PowerShell modules and binaries included to make the process of Post Exploitation easy-er.
What I tried was to build an “all in one” Post Exploitation tool which I could use to bypass all mitigations solutions (or at least some off), and that has all relevant tooling included. 
You can use it to perform modern attacks within Active Directory environments and create awareness within your Blue team so they can build the right defense strategies.

### How to Compile it:

To compile p0wnedShell you need to import this project within Microsoft Visual Studio or if you don't have access to a Visual Studio installation, you can compile it as follows:

To Compile as x86 binary:

```
cd \Windows\Microsoft.NET\Framework\v4.0.30319

csc.exe  /unsafe /reference:"C:\p0wnedShell\System.Management.Automation.dll" /reference:System.IO.Compression.dll /win32icon:C:\p0wnedShell\p0wnedShell.ico /out:C:\p0wnedShell\p0wnedShellx86.exe /platform:x86 "C:\p0wnedShell\*.cs"
```

To Compile as x64 binary:

```
cd \Windows\Microsoft.NET\Framework64\v4.0.30319

csc.exe  /unsafe /reference:"C:\p0wnedShell\System.Management.Automation.dll" /reference:System.IO.Compression.dll /win32icon:C:\p0wnedShell\p0wnedShell.ico /out:C:\p0wnedShell\p0wnedShellx64.exe /platform:x64 "C:\p0wnedShell\*.cs"
```

p0wnedShell uses the System.Management.Automation namespace, so make sure you have the System.Management.Automation.dll within your source path when compiling outside of Visual Studio.

### How to use it:

Just the run the executables or...

To run as x86 binary and bypass Applocker (Credits for this great bypass go to Casey Smith aka subTee):

```
cd \Windows\Microsoft.NET\Framework\v4.0.30319 (Or newer .NET version folder)

InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx86.exe
```

To run as x64 binary and bypass Applocker:

```
cd \Windows\Microsoft.NET\Framework64\v4.0.30319 (Or newer .NET version folder)

InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx64.exe
```

### Shout-outs:

p0wnedshell is heavily based on tools and knowledge from people like harmj0y, the guys from Powersploit, Sean Metcalf, SubTee, Nikhil Mittal, Besimorhino, Benjamin Delpy e.g. So shout-outs go to them and of course to our friends in Redmond for giving us access to a very powerfull hacking language.

### Contact:

To report an issue or request a feature, feel free to contact me at:
Cornelis ```at``` dePlaa.com or [@Cn33lis](https://twitter.com/Cneelis)


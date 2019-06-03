### Changelog:

#### Version 2.6:

* Added a recent version of Mimikatz.
* Updated some PowerShell script/modules.
* Fixed some PowerSploit scripts so they work "again" in latest Windows 10 builds.

#### Version 2.5:

* p0wnedShell can now be run from a Meterpreter shell.
* Added a recent version of Mimikatz and changed the in memory PE loader to Native C# code.
* Ported EasySystem (using namedpipe impersonation) to native C# code (instead of using reflective PE injection).
* Fixed a Proxy authentication issue within the domainfronting enabled Meterpreter stager.
* Added option to masquerade the p0wnedShell process (PEB) so it has the appearance of a another process (notepad.exe e.g.).
* Added -parent command line option to start p0wnedShell using another Parent Process ID (svchost e.g.).
* Using the same technique to start p0wnedShell with another Parent Process, we can also create a new process with a system token. 

#### Version 2.0:

* Updated all PowerShell script/modules.
* Added new Exploits/Attacks and automation.

#### Version 1.4.1:

* Includes a new Potato/Tater (WPAD) Local Privilege Escalation trigger i found in the Office 2016/365 ClickToRun service.
  ClickToRun issue Reported to MSRC on 4/29/2016 (WPAD/NTLM Loopback relay issue can now be mitigated using MS16-077).

#### Version 1.4:

* Includes a bypass method for Amsi (Antimalware Scan Interface) within Windows 10.

#### Version 1.3:

* PowerSploit tools updated.
* Updated Mimikatz to latest version.
* Updated MS14-068 Exploit (Kekeo) to latest version.
* New version of Didier Stevens modification of ReactOS Command Prompt incl. Backup Privileges.
* Added Tater, the PowerShell implementation of the Hot Potato Windows Privilege Escalation exploit.
* Added automation to get a SYSTEM command shell using Token Manipulation (Invoke-TokenManipulation).
* Added automation to find machines in the Domain where Domain Admins are logged into (PowerView).

#### Version 1.2:

* First Public Release.

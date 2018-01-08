using System;
using System.IO;
using System.DirectoryServices.ActiveDirectory;

namespace p0wnedShell
{
    class SitAwareness
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Use Invoke-UserHunter and/or BloodHound to identify Attack Paths  *" };
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Find machines in the Domain where Domain Admins are logged into.");
            Console.WriteLine();
            Console.WriteLine(" 2. BloodHound: Six Degrees of Domain Admin.");
            Console.WriteLine();
            Console.WriteLine(" 3. Back.");
            Console.Write("\nEnter choice: ");

            int userInput = 0;
            while (true)
            {
                try
                {
                    userInput = Convert.ToInt32(Console.ReadLine());
                    if (userInput < 1 || userInput > 3)
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
                    AdminHunter();
                    break;
                case 2:
                    BloodHound();
                    break;
                default:
                    break;
            }
        }
        public static void AdminHunter()
        {
            string[] toPrint = { "* Finds machines in the Domain where Domain Admins are logged into. *" };
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

            Console.Write("[+] Please wait, this could take a while on large Domains...\n");

            string UserHunter = "Invoke-UserHunter -CheckAccess";
            try
            {
                P0wnedListener.Execute(UserHunter);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void BloodHound()
        {
            string[] toPrint = { "* BloodHound: Six Degrees of Domain Admin.                          *" };
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
            Console.WriteLine("[+] BloodHound uses graph theory to reveal the hidden and often unintended relationships");
            Console.WriteLine("[+] within an Active Directory environment. Attackers can use BloodHound to easily identify");
            Console.WriteLine("[+] highly complex attack paths that would otherwise be impossible to quickly identify.");
            Console.WriteLine("[+] Defenders can use BloodHound to identify and eliminate those same attack paths.");
            Console.WriteLine("[+] More Info: https://github.com/BloodHoundAD/BloodHound/wiki\n");
            Console.ResetColor();

            Console.WriteLine("[+] Please wait, this could take a while on large Domains...\n");

            string UserHunter = "Invoke-BloodHound -CompressData -RemoveCSV";
            try
            {
                P0wnedListener.Execute(UserHunter);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            if (File.Exists(Program.P0wnedPath() + "\\BloodHound.bin"))
            {
                File.Delete(Program.P0wnedPath() + "\\BloodHound.bin");
            }

                Console.WriteLine("\n[+] BloodHound Data is saved in a zip file in the current directory.");
            Console.WriteLine("[+] You can unzip and import the csv's in your offline BloodHound Installation.");

            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

    }
}
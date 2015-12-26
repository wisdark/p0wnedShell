/*
Compress Binary file to Base64 String - by Cn33liz 2015

Compile:
cd \Windows\Microsoft.NET\Framework64\v4.0.30319
csc.exe  /out:"C:\Utils\CompressString.exe" /platform:x64 "C:\Utils\CompressString.cs"

ByteEncode EXE or DLL with PowerShell:
Get-Content -Encoding byte -path "C:\Temp\Mimikatz.exe" -ReadCount 0 > ByteArray.txt
CompressString.exe ByteArray.txt Base64String.txt

*/

using System;
using System.Text;
using System.IO;
using System.IO.Compression;


class Program
{		
	public static void Compress(string text, string outfile)
	{
		byte[] buffer = Encoding.UTF8.GetBytes(text);
		MemoryStream ms = new MemoryStream();
		
		using (GZipStream zip = new GZipStream(ms, CompressionMode.Compress, true))
		{
			zip.Write(buffer, 0, buffer.Length);
		}

		ms.Position = 0;
		MemoryStream outStream = new MemoryStream();

		byte[] compressed = new byte[ms.Length];
		ms.Read(compressed, 0, compressed.Length);

		byte[] gzBuffer = new byte[compressed.Length + 4];
		System.Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length);
		System.Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4);
		
		string MimiBase64 = Convert.ToBase64String (gzBuffer);
		File.WriteAllText (outfile, MimiBase64);
		
		Console.WriteLine ("Base64 string saved as "+outfile+"\n");
		//return Convert.ToBase64String (gzBuffer);
	}
	
	public static void Main (string[] args)
	{
		if (args.Length != 2)
		{
			Console.WriteLine("\nUsage: CompressString.exe <ByteArray.txt> <Base64String.txt>");
			Environment.Exit(1);
		}
		if (File.Exists(args[0]))
		{
			string BytesFile = args[0];
			string Bytes = File.ReadAllText(BytesFile).Replace(Environment.NewLine, " ");
			File.WriteAllText (@"ByteString.txt", Bytes);
			
			string BytesArray = File.ReadAllText(@"ByteString.txt");
				
			Console.WriteLine ("\nNow let's Compress\n");
			Compress(BytesArray, args[1]);
			Console.WriteLine ("Done!");
		}
		else
		{
			Console.WriteLine("\nFile"+args[0]+" does not exist...");
			Environment.Exit(1);
		}
		
	}
}

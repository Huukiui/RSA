using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RSA
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string? publicKey = "";
            string? privateKey = "";

            while (true)
            {
                Console.Clear();
                Console.WriteLine($"1. Generate new keys");
                Console.WriteLine("2. Import keys");
                Console.WriteLine("3. Encrypt String");
                Console.WriteLine("4. Encrypt File");
                Console.WriteLine("5. Decrypt File");
                Console.WriteLine("6. Compare speed with RC5");
                Console.WriteLine("7. Exit");
                Console.Write("Enter your choice: ");

                var choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        (publicKey, privateKey) = GenerateAndSaveKeys();
                        break;
                    case "2":
                        (publicKey, privateKey) = ImportOldKeys();
                        break;
                    case "3":
                        EncryptString(publicKey);
                        break;
                    case "4":
                        EncryptFile(publicKey);
                        break;
                    case "5":
                        DecryptFile(privateKey);
                        break;
                    case "6":
                        CompareWithRC5(publicKey, privateKey, 16, 12, 16, "abc");
                        break;
                    case "7":
                        return;
                    default:
                        Console.WriteLine("Invalid choice. Try again.");
                        break;
                }
            }
        }

        public static (string, string) GenerateAndSaveKeys()
        {
            Console.WriteLine("Enter a file name to save public key:");
            string publicKeyFile = Console.ReadLine();
            Console.WriteLine("Enter a file name to save private key:");
            string privateKeyFile = Console.ReadLine();
 
            (string publicKey, string privateKey) = RSA.GenerateKeys();

            Console.WriteLine($"Public: {publicKey}");
            Console.WriteLine($"Private: {privateKey}");

            using (FileStream fs = new FileStream(publicKeyFile, FileMode.OpenOrCreate))
            {
                fs.Write(Encoding.UTF8.GetBytes(publicKey));
            }
            using (FileStream fs = new FileStream(privateKeyFile, FileMode.OpenOrCreate))
            {
                fs.Write(Encoding.UTF8.GetBytes(privateKey));
            }
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
            return (publicKey, privateKey);
        }

        public static (string, string) ImportOldKeys()
        {
            Console.WriteLine("Enter a file name to get public key:");
            string publicKeyFile = Console.ReadLine();

            while (!File.Exists(publicKeyFile))
            {
                Console.WriteLine("File doesnt exist. Try again:");
                publicKeyFile = Console.ReadLine();
            }

            Console.WriteLine("Enter a file name to get private key:");
            string privateKeyFile = Console.ReadLine();

            while (!File.Exists(privateKeyFile))
            {
                Console.WriteLine("File doesnt exist. Try again:");
                privateKeyFile = Console.ReadLine();
            }
            string publicKey = Encoding.UTF8.GetString(File.ReadAllBytes(publicKeyFile));
            string privateKey = Encoding.UTF8.GetString(File.ReadAllBytes(privateKeyFile));
            Console.WriteLine($"Public: {publicKey}");
            Console.WriteLine($"Private: {privateKey}");
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
            return (publicKey, privateKey);
        }

        public static void EncryptString(string publicKey)
        {
            Console.WriteLine("Enter a string to ecnrypt:");
            string input = Console.ReadLine();

            Console.WriteLine("Enter a file name to save result:");
            string filePathToSave = Console.ReadLine();

            using(MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(input)))
            {
                RSA.Encrypt(publicKey, ms, filePathToSave);
            }
        }

        public static void EncryptFile(string publicKey)
        {
            Console.WriteLine("Enter a file name to ecnrypt:");
            string inputFile = Console.ReadLine();

            while (!File.Exists(inputFile))
            {
                Console.WriteLine("File doesnt exist. Try again:");
                inputFile = Console.ReadLine();
            }

            Console.WriteLine("Enter a file name to save result:");
            string filePathToSave = Console.ReadLine();

            using (FileStream fs = new FileStream(inputFile, FileMode.Open))
            {
                RSA.Encrypt(publicKey, fs, filePathToSave);
            }
        }

        public static void DecryptFile(string privateKey)
        {
            Console.WriteLine("Enter a file name to decrypt:");
            string inputFile = Console.ReadLine();

            while (!File.Exists(inputFile))
            {
                Console.WriteLine("File doesnt exist. Try again:");
                inputFile = Console.ReadLine();
            }

            Console.WriteLine("Enter a file name to save result:");
            string filePathToSave = Console.ReadLine();

            RSA.Decrypt(privateKey, inputFile, filePathToSave);
        }

        public static void CompareWithRC5(string publicKey, string privateKey, int W, int R, int B, string pass)
        {
            Console.WriteLine("Enter the path to the file you want to encrypt:");
            string inputFile = Console.ReadLine();

            
            while (!File.Exists(inputFile))
            {
                Console.WriteLine("File doesn't exist. Try again:");
                inputFile = Console.ReadLine();
            }

            
            string fileExtension = Path.GetExtension(inputFile);

            RC5 rc = new RC5(W, R, B, pass);

            var stopwatch = new Stopwatch();
            using (FileStream fs = new FileStream(inputFile, FileMode.Open))
            {
                stopwatch.Start();
                rc.EncryptDataCBCPad(fs, "RC5.data");
                stopwatch.Stop();
            }
            Console.WriteLine($"RC5 encrypted in {stopwatch.ElapsedMilliseconds} ms.");

            stopwatch = new Stopwatch();
            using (FileStream fs = new FileStream(inputFile, FileMode.Open))
            {
                stopwatch.Start();
                RSA.Encrypt(publicKey, fs, "RSA.data");
                stopwatch.Stop();
            }
            Console.WriteLine($"RSA encrypted in {stopwatch.ElapsedMilliseconds} ms.");

            stopwatch = new Stopwatch();
            stopwatch.Start();
            rc.DecryptDataCBCPad("RC5.data", $"RC5result{fileExtension}");
            stopwatch.Stop();
            Console.WriteLine($"\nRC5 decrypted in {stopwatch.ElapsedMilliseconds} ms.");

            stopwatch = new Stopwatch();
            stopwatch.Start();
            RSA.Decrypt(privateKey, "RSA.data", $"RSAresult{fileExtension}");
            stopwatch.Stop();
            Console.WriteLine($"RSA decrypted in {stopwatch.ElapsedMilliseconds} ms.");

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }

    }
}

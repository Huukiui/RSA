using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RSA
{
    public class RSA
    {
        public static (string publicKey, string privateKey) GenerateKeys()
        {
            string publicKey;
            string privateKey;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                publicKey = rsa.ToXmlString(false);
                privateKey = rsa.ToXmlString(true);
            }
            return (publicKey, privateKey);
        }

        public static void Encrypt(string publicKey, Stream input, string destination)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(publicKey);
                using (BinaryWriter bw = new BinaryWriter(File.Open(destination, FileMode.Create)))
                {
                    byte[] buffer = new byte[245];
                    int bytesRead;

                    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        bw.Write(rsa.Encrypt(buffer, false));
                    }
                    
                }
            }
        }  
        
        public static void Decrypt(string privateKey, string source, string destination)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(privateKey);
                using (BinaryReader br = new BinaryReader(File.Open(source, FileMode.Open)))
                {
                    using (BinaryWriter bw = new BinaryWriter(File.Open(destination, FileMode.Create)))
                    {
                        byte[] buffer = new byte[256];
                        int bytesRead;
                        while ((bytesRead = br.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            bw.Write(rsa.Decrypt(buffer, false));
                        }
                    }
                }
            }
        }
    }
}

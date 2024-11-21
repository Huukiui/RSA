using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    public class RC5
    {
        public const int MinRounds = 0;
        public const int MaxRounds = 255;
        public const int MinSecretKeyOctets = 0;
        public const int MaxSecretKeyOctets = 255;
        public const int MinKeyByteSize = 0;
        public const int MaxKeyByteSize = 255;

        public const ushort P16 = 0xB7E1;
        public const uint P32 = 0xB7E15163;
        public const ulong P64 = 0xB7E151628AED2A6B;

        public const ushort Q16 = 0x9E37;
        public const uint Q32 = 0x9E3779B9;
        public const ulong Q64 = 0x9E3779B97F4A7C15;

        public int w;
        public int b;
        public int r;
        public int u;
        public string? password;

        ulong[] L;
        public int t;

        private Type WordType;

        private ulong[] S;

        public RC5(int W, int R, int B, string? pass)
        {
            t = 2 * (R + 1);
            w = W;
            b = B;
            r = R;
            password = pass;

            S = new ulong[t];

            WordType = w switch
            {
                16 => typeof(ushort),
                32 => typeof(uint),
                64 => typeof(ulong),
                _ => throw new ArgumentException("Unsupported word size")
            };

            KeyExpansion(TransformKey(password), GetP(w), GetQ(w));


        }

        private ulong GetP(int w)
        {
            return w switch
            {
                16 => (ushort)0xB7E1,                        // для w = 16
                32 => (uint)0xB7E15163,                    // для w = 32
                64 => (ulong)0xB7E151628AED2A6B,          // для w = 64
                _ => throw new ArgumentException("Unsupported word size")
            };
        }

        private ulong GetQ(int w)
        {
            return w switch
            {
                16 => (ushort)0x9E37,                        // для w = 16
                32 => (uint)0x9E3779B9,                    // для w = 32
                64 => (ulong)0x9E3779B97F4A7C15,          // для w = 64
                _ => throw new ArgumentException("Unsupported word size")
            };
        }

        private void KeyExpansion(byte[] key, ulong P, ulong Q)
        {
            u = w / 8; // кількість байтів у слові
            int c = (int)Math.Ceiling((double)(b / u));
            L = new ulong[c];

            var keysList = key.ToList();
            for (int i = b; i < c * u; i++)
            {
                keysList.Add(0);
            }

            var paddedKeys = keysList.ToArray();
            // Конструюємо L[] з ключа
            for (int k = b - 1; k >= 0; k--)
            {
                if (L[k / u] == null)
                {
                    L[k / u] = 0;
                }
                L[k / u] = RotateLeft(L[k / u], 8, w) + paddedKeys[k];
            }

            // Ініціалізуємо таблицю S
            S[0] = P;
            for (int i = 1; i < t; i++)
            {
                S[i] = S[i - 1] + Q;
            }


            // Продовжуємо міксування ключа
            ulong A = 0;
            ulong B = 0;
            int iIndex = 0, jIndex = 0;

            for (int k = 0, v = 3 * Math.Max(c, t); k < v; k++)
            {
                S[iIndex] = RotateLeft(S[iIndex] + A + B, 3, w);
                A = S[iIndex];
                L[jIndex] = RotateLeft(L[jIndex] + A + B, (ulong)(A + B), w);
                B = L[jIndex];


                iIndex = (iIndex + 1) % t;
                jIndex = (jIndex + 1) % c;

            }
        }

        public (ulong, ulong) Encrypt(ulong a, ulong b)
        {
            ulong A = a + S[0];
            ulong B = b + S[1];

            for (int i = 1; i <= r; i++)
            {
                A = RotateLeft(A ^ B, (ulong)B, w) + S[2 * i];
                B = RotateLeft(B ^ A, (ulong)A, w) + S[2 * i + 1];
            }

            return (A, B);
        }

        public (ulong, ulong) Decrypt(ulong a, ulong b)
        {
            ulong A = a;
            ulong B = b;

            for (int i = r; i > 0; i--)
            {
                B = RotateRight(B - S[2 * i + 1], (ulong)A, w) ^ A;
                A = RotateRight(A - S[2 * i], (ulong)B, w) ^ B;
            }

            A -= S[0];
            B -= S[1];

            return (A, B);
        }

        // Операція циклічного зсуву вліво для динамічного типу
        private ulong RotateLeft(ulong value, ulong shift, int length)
        {
            value = CutData(value);
            shift %= (uint)length;
            int ishift = (int)shift;
            return (value << ishift) | (value >> (length - ishift));
        }
        private ulong RotateRight(ulong value, ulong shift, int length)
        {
            value = CutData(value);
            shift %= (uint)length;
            int ishift = (int)shift;
            return (value >> ishift) | (value << (length - ishift));
        }

        private byte[] TransformKey(string keyPhrase)
        {
            byte[] key = MD5.ComputeMD5ForStringToBytes(keyPhrase);
            byte[] finalKey;
            if (b == 8)
            {
                finalKey = new byte[8];
                Array.Copy(key, 0, finalKey, 0, 8);
            }
            else if (b == 16)
            {
                finalKey = new byte[16];
                Array.Copy(key, 0, finalKey, 0, 16);
            }
            else
            {
                finalKey = new byte[32];
                Array.Copy(key, 0, finalKey, 16, 16);
                var tmp = MD5.ComputeMD5ForBytes(key);
                Array.Copy(tmp, 0, finalKey, 0, 16);
            }

            return finalKey;
        }

        private dynamic CutData(dynamic data)
        {
            return WordType switch
            {
                { } when WordType == typeof(ushort) => (ushort)data,
                { } when WordType == typeof(uint) => (uint)data,
                { } when WordType == typeof(ulong) => (ulong)data
            };
        }

        public (ulong, ulong) FormIV()
        {
            LinearCongruentialGenerator lc = new LinearCongruentialGenerator(16807, 0, 2147483647, new Random().Next());
            long[] randomIV = new long[4];
            for (int i = 0; i < 4; i++)
            {
                randomIV[i] = lc.Next();
            }
            ulong[] IV =
            [
                ((ulong)randomIV[0] << 32) | ((ulong)randomIV[1] & 0xFFFFFFFF),
                ((ulong)randomIV[2] << 32) | ((ulong)randomIV[3] & 0xFFFFFFFF),
            ];
            ulong bw1 = CutData(IV[0]);
            ulong bw2 = CutData(IV[1]);

            return (bw1, bw2);
        }

        public void EncryptDataCBCPad(Stream DataStream, string filepath)
        {
            ulong iv1;
            ulong iv2;
            (iv1, iv2) = FormIV();
            ulong Ci_1_1 = iv1; //original IV
            ulong Ci_1_2 = iv2; //original IV
            ulong P1;
            ulong P2;
            ulong C1;
            ulong C2;
            (iv1, iv2) = Encrypt(iv1, iv2); //encryprted IV

            byte[] buffer = new byte[2 * u];
            int bytesRead;
            ulong half1;
            ulong half2;

            using (BinaryWriter writer = new BinaryWriter(File.Open(filepath, FileMode.Create)))
            {
                if (w == 16)
                {
                    writer.Write((ushort)iv1);
                    writer.Write((ushort)iv2);
                }
                else if (w == 32)
                {
                    writer.Write((uint)iv1);
                    writer.Write((uint)iv2);
                }
                else
                {
                    writer.Write((ulong)iv1);
                    writer.Write((ulong)iv2);
                }
                while ((bytesRead = DataStream.Read(buffer, 0, buffer.Length)) == 2 * u)
                {
                    half1 = 0;
                    half2 = 0;
                    for (int i = u - 1; i >= 0; i--)
                    {
                        half1 = (half1 << 8) | buffer[i];
                    }
                    for (int i = 2 * u - 1; i >= u; i--)
                    {
                        half2 = (half2 << 8) | buffer[i];
                    }
                    P1 = half1;//forming block
                    P2 = half2;

                    P1 = P1 ^ Ci_1_1;//XOR block with previous
                    P2 = P2 ^ Ci_1_2;
                    (C1, C2) = Encrypt(P1, P2);//Encrypt block
                    if (w == 16)
                    {
                        writer.Write((ushort)C1);
                        writer.Write((ushort)C2);
                    }
                    else if (w == 32)
                    {
                        writer.Write((uint)C1);
                        writer.Write((uint)C2);
                    }
                    else
                    {
                        writer.Write((ulong)C1);
                        writer.Write((ulong)C2);
                    }

                    (Ci_1_1, Ci_1_2) = (C1, C2); // saving Ci-1 for XOR

                }
                byte[] finalBlock = new byte[2 * u];
                if (bytesRead != 0)
                    Buffer.BlockCopy(buffer, 0, finalBlock, 0, bytesRead);
                byte bytesAdded = (byte)(2 * u - bytesRead);
                for (int i = bytesRead; i < 2 * u; i++)
                {
                    finalBlock[i] = bytesAdded;
                }
                half1 = 0;
                half2 = 0;
                for (int i = u - 1; i >= 0; i--)
                {
                    half1 = (half1 << 8) | finalBlock[i];
                }
                for (int i = 2 * u - 1; i >= u; i--)
                {
                    half2 = (half2 << 8) | finalBlock[i];
                }
                P1 = half1;
                P2 = half2;

                P1 = P1 ^ Ci_1_1;
                P2 = P2 ^ Ci_1_2;
                (C1, C2) = Encrypt(P1, P2);
                if (w == 16)
                {
                    writer.Write((ushort)C1);
                    writer.Write((ushort)C2);
                }
                else if (w == 32)
                {
                    writer.Write((uint)C1);
                    writer.Write((uint)C2);
                }
                else
                {
                    writer.Write((ulong)C1);
                    writer.Write((ulong)C2);
                }


            }
        }

        public void DecryptDataCBCPad(string filepath, string filePathToSave)
        {
            using (FileStream fileStream = File.OpenRead(filepath))
            {
                using (BinaryWriter writer = new BinaryWriter(File.Open(filePathToSave, FileMode.Create)))
                {
                    byte[] buffer = new byte[2 * u];
                    int bytesRead;
                    ulong Ci_1_1 = 0;
                    ulong Ci_1_2 = 0;
                    ulong P1;
                    ulong P2;
                    ulong C1;
                    ulong C2;
                    ulong half1;
                    ulong half2;
                    bool decryptIV = false;
                    while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) == 2 * u)
                    {
                        if (!decryptIV)
                        {
                            half1 = 0;
                            half2 = 0;
                            for (int i = u - 1; i >= 0; i--)
                            {
                                half1 = (half1 << 8) | buffer[i];
                            }
                            for (int i = 2 * u - 1; i >= u; i--)
                            {
                                half2 = (half2 << 8) | buffer[i];
                            }
                            C1 = half1;//first half of IV
                            C2 = half2;//Second half of IV
                            (Ci_1_1, Ci_1_2) = Decrypt(C1, C2); //Decrypted IV

                            decryptIV = true;

                        }
                        else
                        {
                            half1 = 0;
                            half2 = 0;
                            for (int i = u - 1; i >= 0; i--)
                            {
                                half1 = (half1 << 8) | buffer[i];
                            }
                            for (int i = 2 * u - 1; i >= u; i--)
                            {
                                half2 = (half2 << 8) | buffer[i];
                            }
                            C1 = half1; //reading first half of encrypted block
                            C2 = half2; //reading second half of encrypted block
                            (P1, P2) = Decrypt(C1, C2); //Decrypting
                            P1 = P1 ^ Ci_1_1;
                            P2 = P2 ^ Ci_1_2; //XOR with previous encrypted block
                            Ci_1_1 = C1;
                            Ci_1_2 = C2; //Save Ci for being next Ci-1
                            if (fileStream.Position == fileStream.Length)
                            {
                                byte[] finalByteBlock = new byte[2 * u];
                                byte[] p1Bytes = GetBytesAfterDecryption(P1);
                                byte[] p2Bytes = GetBytesAfterDecryption(P2);
                                Array.Copy(p1Bytes, 0, finalByteBlock, 0, u);
                                Array.Copy(p2Bytes, 0, finalByteBlock, u, u);

                                int padBytesCount = finalByteBlock[finalByteBlock.Length - 1];
                                writer.Write(finalByteBlock[0..(finalByteBlock.Length - padBytesCount)]);

                            }
                            else
                            {
                                writer.Write(GetBytesAfterDecryption(P1));
                                writer.Write(GetBytesAfterDecryption(P2));
                            }



                        }
                    }
                }

            }
        }


        // Допоміжний метод для виведення байтів
        public void PrintBytes(byte[] bytes)
        {
            foreach (byte b in bytes)
            {
                Console.Write($"{b:X2} "); // Виводимо байти у шістнадцятковому форматі
            }
            Console.WriteLine();
        }

        public byte[] GetBytesAfterDecryption(ulong value) => w switch
        {
            16 => BitConverter.GetBytes((ushort)value),
            32 => BitConverter.GetBytes((uint)value),
            64 => BitConverter.GetBytes((ulong)value)
        };
    }
}
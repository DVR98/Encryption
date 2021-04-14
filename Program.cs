using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Security.Permissions;
using System.Security;
using System.Runtime.InteropServices;

namespace Encryption
{
    class Program
    {
        //Cryptography is about encrypting and decrypting data
        //With encryption, you take plain text and then run an algorithm over it. The resulting data looks like a random byte sequence called ciphertext. 
        //Decryption is the opposite process: The byte sequence is transformed into original plain text data
        //In cryptography, you can keep your algorithm secret, or you can use a public algorithm and keep your key secret.
        //Keeping your algorithm secret is often impractical because you would need to switch algorithms each time someone leaked the algorithm. Instead a key is kept secret. 
        //A key is used by an algorithm to control the encryption process.
        //The difference in symmetric and asymmetric encryption strategies lies in the way this key is used. 
        //Symmetric algorithm uses one single key to encrypt and decrypt the data. You need to pass your original key to the receiver so he can decrypt your data.
        //An asymmetric algorithm uses two different keys that are mathematically related to each other. One key is completely public and can be read and used by everyone. The other part is private and should never be shared with someone else. When you encrypt something with the public key, it can be decrypted by using the private key
        //Symmetric encryption is faster than asymmetric encryption and is well-suited for larger data sets. Asymmetric encryption is not optimized for encrypting long messages, but it can be very useful for decrypting a small key
        //cryptography classes can be found in the System.Security.Cryptography namespace
        static void Main(string[] args)
        {
            Console.WriteLine("Symmetric Encryption/Decryption:");
            //Symmetric algorithm method
            SymmetricAlgorithm();
            Console.WriteLine("Asymmetric Encryption/Decryption:");
            //Asymmetric algorithm method
            AssymetricAlgorithm();
            //Hashing:
            Console.WriteLine("Hashing:");
            UseHashing();
            Console.WriteLine("Secure Strings:");
            ConvertToSecureString();
        }

        //Symmetric Encryption
        //The SymmetricAlgorithm class has both a method for creating an encryptor and a decryptor. 
        //By using the CryptoStream class, you can encrypt or decrypt a byte sequence.
        public static void SymmetricAlgorithm()
        {
            string secret_data = "Impossible! Perhaps the archives are incomplete.";

            using (SymmetricAlgorithm symmetricAlgorithm = 
                new AesManaged())
            {
                byte[] encrypted = SymmetricEncrypt(symmetricAlgorithm, secret_data);
                string decrypted_result = SymmetricDecrypt(symmetricAlgorithm, encrypted);

                // Displays: My secret data! 
                Console.WriteLine("Encrypted text:   {0}", secret_data); 
                Console.WriteLine("Decrypted result: {0}", decrypted_result);
            }
        }

        //Symmetric Encryption
        static byte[] SymmetricEncrypt(SymmetricAlgorithm aesAlg, string plainText)
        {
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            //Use CryptoStream class to encrypt data
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = 
                    new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        //Symmetric Decryption
        static string SymmetricDecrypt(SymmetricAlgorithm aesAlg, byte[] cipherText)
        {
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            //Use CryptoStream class to decrypt data
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt =
                    new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        var result =  srDecrypt.ReadToEnd();
                        return result;
                    }
                }
            }
        }
        
        //Asymmetric encryption. 
        //You can use the RSACryptoServiceProviderand DSACryptoServiceProvider classes. 
        //When working with asymmetric encryption, you use public key from another party. 
        //You encrypt the data using the public key so only the other party can decrypt the data with their private key.
        public static void AssymetricAlgorithm(){
            //Create Public- and Private Keys using the RSACryptoService class
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string publicKeyXML = rsa.ToXmlString(false);
            string privateKeyXML = rsa.ToXmlString(true);

            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes("Only a sith deals in absolutes.");

            //Encrypt data using the RSACryptoService class
            byte[] encryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(publicKeyXML);
                encryptedData = RSA.Encrypt(dataToEncrypt, false);
                Console.WriteLine("Encrypted successfully!");
            }

            //Decrypt data using the RSACryptoService class
            byte[] decryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(privateKeyXML);
                decryptedData = RSA.Decrypt(encryptedData, false);
                Console.WriteLine("Decrypted successfully!");
            }

            //Display result
            string decryptedString = ByteConverter.GetString(decryptedData);
            Console.WriteLine("Decrypted result: {0}", decryptedString); 
        }

        //Hashing
        //Hashing is the process of taking a large set of data and mapping it to a smaller data set of fixed length. For example, mapping all names to a specific integer. 
        //Instead of checking the complete name, you would have to use only an integer value.
        public static void UseHashing(){
            var values = new int[11];
            var rand = new Random();
            var set = new Set<int>();

            for (int i = 0; i < 10; i++)
            {
                values[i] = rand.Next(1, 13);
                set.Insert(values[i]);
            }
            
            var contains = set.Contains(values[3]);
            Console.WriteLine("Bucket contains {0}? Answer: {1}", values[3], contains);

            Console.WriteLine("Using SHA256Managed to calculate a hash code:");
            UnicodeEncoding byteConverter = new UnicodeEncoding();
            SHA256 sha256 = SHA256.Create();

            string data = "A paragraph of text";
            byte[] hashA = sha256.ComputeHash(byteConverter.GetBytes(data));

            data = "A paragraph of changed text";
            byte[] hashB = sha256.ComputeHash(byteConverter.GetBytes(data));

            data = "A paragraph of text";
            byte[] hashC = sha256.ComputeHash(byteConverter.GetBytes(data));

            Console.WriteLine(hashA.SequenceEqual(hashB)); // Displays: false
            Console.WriteLine(hashA.SequenceEqual(hashC)); // Displays: true

        }
        class Set<T>
        {
            private List<T>[] buckets = new List<T>[100];

            public void Insert(T item)
            {
                int bucket = GetBucket(item.GetHashCode());
                if (Contains(item, bucket))
                    return;
                if (buckets[bucket] == null)
                    buckets[bucket] = new List<T>();
                buckets[bucket].Add(item);
                Console.WriteLine("{0} Added successfully", item);
            }
            public bool Contains(T item)
            {
                return Contains(item, GetBucket(item.GetHashCode()));
            }

            private int GetBucket(int hashcode)
            {
                // A Hash code can be negative. 
                // To make sure that you end up with a positive value cast the value to an unsigned int. 
                //The unchecked block makes sure that you can cast a value larger then int to an int safely.
                unchecked
                {
                    return (int)((uint)hashcode % (uint)buckets.Length);
                }
            }

            private bool Contains(T item, int bucket)
            {
                if (buckets[bucket] != null)
                    foreach (T member in buckets[bucket])
                        if (member.Equals(item))
                            return true;
                return false;
            }
        }

        //SecureString automatically encrypts its value so the possibility of an attacker finding a plain text version of your string is decreased. 
        //A SecureString is also pinned to a specific memory location. The garbage collector doesn’t move the string around, so you avoid the problem of having multiple copies. 
        //SecureString is a mutable string that can be made read-only when necessary. 
        //SecureString implements IDisposable so you can make sure that its content is removed from memory whenever you’re done with it
        public static void ConvertToSecureString(){
            using (SecureString ss = new SecureString())
            {
                Console.Write("Please enter a sentence: ");
                while (true)
                {
                    ConsoleKeyInfo cki = Console.ReadKey(true);
                    if (cki.Key == ConsoleKey.Enter) 
                    {
                        Console.WriteLine(string.Empty);
                        ConvertToUnsecureString(ss);
                        break;
                    }
                    ss.AppendChar(cki.KeyChar);
                    Console.Write("*");
                }
                ss.MakeReadOnly();
            }

        }

        public static void ConvertToUnsecureString(SecureString securePassword)
        {
            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                Console.WriteLine("Your Converted Password: {0}", Marshal.PtrToStringUni(unmanagedString));
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

    }
}

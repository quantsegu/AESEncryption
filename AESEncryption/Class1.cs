using System;
using FOTools.Encryption;

namespace AESEncryption
{
    public class EncryptAES
    {
        public static void Main(string[] args)
        {
            string s;
            Scrambler scram = new Scrambler();
            Encryption a = new Encryption();
            
            s = a.RunAES("TurboPascal", true, "Hsbc123");
            Console.WriteLine(scram.scrambleString(s));
            Console.ReadKey();
        }

    }

}
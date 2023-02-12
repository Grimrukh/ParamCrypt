using System.Security.Cryptography;
using System.Text;

namespace ParamCrypt;

public static class Program
{
    static readonly byte[] ds3RegulationKey = Encoding.ASCII.GetBytes("ds3#jn/8_7(rsY9pg55GFN7VFL#+3n/)");
    static readonly byte[] erRegulationKey = {
        0x99, 0xBF, 0xFC, 0x36, 0x6A, 0x6B, 0xC8, 0xC6, 0xF5, 0x82, 0x7D, 0x09, 0x36, 0x02, 0xD6, 0x76,
        0xC4, 0x28, 0x92, 0xA0, 0x1C, 0x20, 0x7F, 0xB0, 0x24, 0xD3, 0xAF, 0x4E, 0x49, 0x3F, 0xEF, 0x99,
    };

    /// <summary>
    /// Decrypts or encrypts DS3 `Data0.bdt` and Elden Ring `regulation.bin` files, which are both just encrypted
    /// DCX-compressed binders (`BND4`) of `Param` files, a la `GameParamBND` in earlier games.
    ///
    /// Simple usage is to just drag a file with one of these four names, which converts to the other in its line:
    ///     `Data0.bdt` | `Data0.parambnd.dcx`
    ///     `regulation.bin` | `regulation.parambnd.dcx`
    ///
    /// Full-control usage (e.g. when format/mode cannot be inferred from input file name) is:
    ///     `ParamCrypt inputFilePath decrypt|encrypt ds3|er [outputFilePath]
    /// with `outputFilePath` auto-detected from `inputFilePath` if omitted (and if possible).
    ///
    /// Either one argument (simple usage) or three/four arguments (full usage) must be given to the executable.
    /// 
    /// Standalone utility adapted from SoulsFormats by TKGP:
    ///     https://github.com/JKAnderson/SoulsFormats/blob/er/SoulsFormats/Util/SFUtil.cs
    /// </summary>
    public static void Main(string[] args)
    {
        if (args.Length is 0 or 2)
        {
            ShowUsage();
            return;
        }
        
        string inputFilePath = args[0];
        bool doEncrypt;
        byte[] key;
        string outputFilePath;

        if (!File.Exists(args[0]))
        {
            Console.WriteLine($"ERROR: Input file does not exist: {inputFilePath}");
            return;
        }

        if (args.Length == 1)
        {
            
            string inputFileName = Path.GetFileName(inputFilePath);
            switch (inputFileName)
            {
                case "Data0.bdt":
                    doEncrypt = false;
                    key = ds3RegulationKey;
                    outputFilePath = GetPathWithExtension(inputFilePath, ".parambnd.dcx");
                    break;
                case "Data0.parambnd.dcx":
                    doEncrypt = true;
                    key = ds3RegulationKey;
                    outputFilePath = GetPathWithExtension(inputFilePath, ".bdt");
                    break;
                case "regulation.bin":
                    doEncrypt = false;
                    key = erRegulationKey;
                    outputFilePath = GetPathWithExtension(inputFilePath, ".parambnd.dcx");
                    break;
                case "regulation.parambnd.dcx":
                    doEncrypt = true;
                    key = erRegulationKey;
                    outputFilePath = GetPathWithExtension(inputFilePath, ".bin");
                    break;
                default:
                    Console.WriteLine(
                        $"# ERROR: Cannot auto-determine mode or game from file name '{inputFileName}'. " +
                        "(Must be `Data0.[bdt|parambnd.dcx]` or `regulation.[bin|parambnd.dcx]`.)");
                    return;
            }
        }
        else if (args.Length is 3 or 4)
        {
            string mode = args[1];
            if (mode != "encrypt" && mode != "decrypt")
            {
                Console.WriteLine($"# ERROR: Invalid `mode`: {mode}. Must be `encrypt` or `decrypt`.");
                return;
            }
            doEncrypt = mode == "encrypt";
            
            string gameType = args[2].ToLower();
            switch (gameType)
            {
                case "ds3":
                    key = ds3RegulationKey;
                    break;
                case "er":
                    key = erRegulationKey;
                    break;
                default:
                    Console.WriteLine($"ERROR: Invalid `gameType`: {gameType}. Must be `ds3` or `er`.");
                    return;
            }

            if (args.Length == 4)
            {
                outputFilePath = args[3];
            }
            else
            {
                string ext = doEncrypt ? ".bin" : ".parambnd.dcx";
                outputFilePath = GetPathWithExtension(inputFilePath, ext);
            }
        }
        else
        {
            ShowUsage();
            return;
        }

        byte[] bytes = File.ReadAllBytes(inputFilePath);
        bytes = doEncrypt ? EncryptByteArray(key, bytes) : DecryptByteArray(key, bytes);

        // Create backup if it doesn't already exist.
        if (File.Exists(outputFilePath) && !File.Exists(outputFilePath + ".bak"))
            File.Copy(outputFilePath, outputFilePath + ".bak");
            
        // Write decrypted or encrypted file.
        File.WriteAllBytes(outputFilePath, bytes);
    }

    static string GetPathWithExtension(string path, string newExtension)
    {
        string nameStem = Path.GetFileName(path).Split(".")[0];
        string newName = $"{nameStem}{newExtension}";
        string? dir = Path.GetDirectoryName(path);
        return dir == null ? newName : Path.Combine(dir, newName);
    }

    static void ShowUsage()
    {
        Console.WriteLine("Usage: `ParamCrypt inputFilePath [encrypt|decrypt] [ds3|er] [outputFilePath]`");
        Console.WriteLine("    If only `inputFilePath` is given, mode and game will be auto-detected from its name if possible.");
        Console.WriteLine("    `outputFilePath` defaults to `inputFilePath` with `.bin` (for encryption) or `.bnd.dcx` (for decryption) extension.");
        Console.WriteLine("    If the output file path already exists, a `.bak` backup will be created (if missing).");
    }

    static byte[] EncryptByteArray(byte[] key, byte[] secret)
    {
        using MemoryStream ms = new();
        var cryptor = Aes.Create();
        cryptor.Mode = CipherMode.CBC;
        cryptor.Padding = PaddingMode.PKCS7;
        cryptor.KeySize = 256;
        cryptor.BlockSize = 128;

        byte[] iv = cryptor.IV;

        using (CryptoStream cs = new(ms, cryptor.CreateEncryptor(key, iv), CryptoStreamMode.Write))
            cs.Write(secret, 0, secret.Length);
        byte[] encryptedContent = ms.ToArray();
        byte[] result = new byte[iv.Length + encryptedContent.Length];

        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length);

        return result;
    }

    static byte[] DecryptByteArray(byte[] key, byte[] secret)
    {
        byte[] iv = new byte[16];
        byte[] encryptedContent = new byte[secret.Length - 16];

        Buffer.BlockCopy(secret, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(secret, iv.Length, encryptedContent, 0, encryptedContent.Length);

        using MemoryStream ms = new();
        var cryptor = Aes.Create();
        cryptor.Mode = CipherMode.CBC;
        cryptor.Padding = PaddingMode.None;
        cryptor.KeySize = 256;
        cryptor.BlockSize = 128;

        using (CryptoStream cs = new(ms, cryptor.CreateDecryptor(key, iv), CryptoStreamMode.Write))
            cs.Write(encryptedContent, 0, encryptedContent.Length);
            
        return ms.ToArray();
    }
}
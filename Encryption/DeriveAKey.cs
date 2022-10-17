public class PasswordDeriveBytes : System.Security.Cryptography.DeriveBytes

//Dependancies
using System;
using System.Security.Cryptography;
using System.Text;

public class PasswordDerivedBytesExample
{

    public static void Main(String[] args)
    {

        // Get a password from the user.
        Console.WriteLine("Enter a password: ");
        string password = Console.ReadLine();

        byte[] pwdBytes = Encoding.Unicode.GetBytes(password);
        
        //A salt is random data used one way to hash sensitive data, e.g. passwords.
        byte[] salt = CreateRandomSalt(7);

        // Create a TripleDESCryptoServiceProvider object.
        TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();

        try //Exception Handling
        {
            Console.WriteLine("Creating a key with PasswordDeriveBytes...");

            // Create a PasswordDeriveBytes object and then create a TripleDES key from the password bytes and salt.
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(pwdBytes, salt);


            // Create the key and set it to the Key property of the TripleDESCryptoServiceProvider object.
            // This example uses the SHA1 algorithm.
            // Due to collision problems with SHA1, Microsoft recommends SHA256 or better.
            tdes.Key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, tdes.IV);


            Console.WriteLine("Operation complete.");
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
        finally //Remove the key and the salt from memory
        {
            // Clear the buffers
            ClearBytes(pwd);
            ClearBytes(salt);

            // Clear the key.
            tdes.Clear();
        }

        Console.ReadLine();
    }

    //////////////////////////////////////////////////////////
    // Helper methods:
    // CreateRandomSalt: Generates a random salt value of the
    //                   specified length.
    //
    // ClearBytes: Clear the bytes in a buffer so they can't
    //             later be read from memory.
    //////////////////////////////////////////////////////////

    public static byte[] CreateRandomSalt(int length)
    {
        // Create a buffer
        byte[] randBytes;

        if (length >= 1)
        {
            randBytes = new byte[length];
        }
        else
        {
            randBytes = new byte[1];
        }

        // Create a new RNGCryptoServiceProvider.
        RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();

        // Fill the buffer with random bytes.
        rand.GetBytes(randBytes);

        // return the bytes.
        return randBytes;
    }

    public static void ClearBytes(byte[] buffer)
    {
        // Check arguments.
        if (buffer == null)
        {
            throw new ArgumentException("buffer");
        }

        // Set each byte in the buffer to 0.
        for (int x = 0; x < buffer.Length; x++)
        {
            buffer[x] = 0;
        }
    }
}

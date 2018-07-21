namespace DiscoNet.Tests
{
    using System;
    using System.Linq;
    using System.Text;

    using DiscoNet.Noise;

    using StrobeNet.Extensions;

    using Xunit;

    public class SymmetricTests
    {
        [Fact]
        public void TestHash()
        {
            var input = Encoding.ASCII.GetBytes("hi, how are you?");
            if (!string.Equals(
                    Symmetric.Hash(input, 32).ToHexString(),
                    "eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75",
                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new Exception("Hash does not produce a correct output");
            }
        }

        [Fact]
        public void TestSum()
        {
            var message1 = Encoding.ASCII.GetBytes("hello");
            var message2 = Encoding.ASCII.GetBytes("how are you good sir?");
            var message3 = Encoding.ASCII.GetBytes("sure thing");

            var fullMessage = message1.Concat(message2).ToArray();

            // Trying with NewHash with streaming and without streaming
            var h1 = new Hash(32);
            h1.Write(message1);
            h1.Write(message2);
            var out1 = h1.Sum();

            var h2 = new Hash(32);
            h2.Write(fullMessage);
            var out2 = h2.Sum();

            if (!out1.SequenceEqual(out2))
            {
                throw new Exception("Sum function does not work");
            }

            // Trying with Hash()
            var out3 = Symmetric.Hash(fullMessage, 32);

            if (!out1.SequenceEqual(out3))
            {
                throw new Exception("Sum function does not work");
            }

            // Trying the streaming even more
            h1.Write(message3);
            out1 = h1.Sum();
            h2.Write(message3);
            out2 = h2.Sum();

            if (!out1.SequenceEqual(out2))
            {
                throw new Exception("Sum function does not work");
            }

            // tring with Hash()
            out3 = Symmetric.Hash(fullMessage.Concat(message3).ToArray(), 32);

            if (!out1.SequenceEqual(out3))
            {
                throw new Exception("Sum function does not work");
            }
        }

        [Fact]
        public void TestDeriveKeys()
        {
            var input = Encoding.ASCII.GetBytes("hi, how are you?");

            if (!string.Equals(
                    Symmetric.DeriveKeys(input, 64).ToHexString(),
                    "d6350bb9b83884774fb9b0881680fc656be1071fff75d3fa94519d50a10b92644e3cc1cae166a60167d7bf00137018345bb8057be4b09f937b0e12066d5dc3df",
                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new Exception("DeriveKeys does not produce a correct output");
            }
        }

        [Fact]
        public void TestProtectVerifyIntegrity()
        {
            var key = "eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75".ToByteArray();

            var message = Encoding.ASCII.GetBytes("hoy, how are you?");

            var plaintextAndTag = Symmetric.ProtectIntegrity(key, message);
            var retrievedMessage = Symmetric.VerifyIntegrity(key, plaintextAndTag);

            if (!message.SequenceEqual(retrievedMessage))
            {
                throw new Exception("Verify did not work");
            }

            // Tamper
            plaintextAndTag[plaintextAndTag.Length - 1] ^= 1;

            bool tamperDetected;
            try
            {
                Symmetric.VerifyIntegrity(key, plaintextAndTag);
                tamperDetected = false;
            }
            catch (Exception)
            {
                tamperDetected = true;
            }

            if (!tamperDetected)
            {
                throw new Exception("Verify did not work");
            }
        }

        [Fact]
        public void TestNonceSize()
        {
            var key = "eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75".ToByteArray();

            var plaitext = Encoding.ASCII.GetBytes("hello, how are you?");

            var ciphertext = Symmetric.Encrypt(key, plaitext);
            if (ciphertext.Length != 19 + 16 + 24)
            {
                throw new Exception("Length of this ciphertext should be 19B(PT) + 16B(TAG) + 24B(NONCE)");
            }
        }

        [Fact]
        public void TestEncryptDecrypt()
        {
            var key = "eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75".ToByteArray();

            var plaintexs = new[]
            {
                "", "a", "ab", "abc", "abcd", "short", "hello, how are you?", "this is very short",
                "this is very long though, like, very very long, should we test very very long things here?"
            };

            foreach (var plaintextString in plaintexs)
            {
                var plaintex = Encoding.ASCII.GetBytes(plaintextString);
                var ciphertext = Symmetric.Encrypt(key, plaintex);
                var decrypted = Symmetric.Decrypt(key, ciphertext);

                if (!plaintex.SequenceEqual(decrypted))
                {
                    throw new Exception("Decrypt did not work");
                }
            }
        }
    }
}
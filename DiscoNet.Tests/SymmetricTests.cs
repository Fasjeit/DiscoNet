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
                "this is very long though, like, very very long, should we test very very long things here?",
                "Domestic cats are similar in size to the other members of the genus Felis, typically weighing "
                + "between 4 and 5 kg (9 and 10 lb).[36] Some breeds, such as the Maine Coon, can occasionally "
                + "exceed 11 kg (24 lb). Conversely, very small cats, less than 2 kg (4 lb), have been reported.[59] "
                + "The world record for the largest cat is 21 kg(50 lb).[60][self - published source] "
                + "The smallest adult cat ever officially recorded weighed around 1 kg(2 lb).[60] "
                + "Feral cats tend to be lighter, as they have more limited access to food than house cats."
                + "The Boston Cat Hospital weighed trapped feral cats, and found the average feral adult "
                + "male to weigh 4 kg(9 lb), and average adult female 3 kg(7 lb).[61] Cats average about "
                + "23–25 cm(9–10 in) in height and 46 cm(18 in) in head / body length(males being larger than females), "
                + "with tails averaging 30 cm(12 in) in length;[62] feral cats may be smaller on average.ats have seven"
                + " cervical vertebrae, as do almost all mammals; 13 thoracic vertebrae(humans have 12); seven lumbar"
                + " vertebrae(humans have five); three sacral vertebrae like most mammals(humans have five);"
                + " and a variable number of caudal vertebrae in the tail(humans have only vestigial caudal"
                + " vertebrae, fused into an internal coccyx).[63]:11 The extra lumbar and thoracic vertebrae"
                + " account for the cat's spinal mobility and flexibility. Attached to the spine are 13 ribs,"
                + " the shoulder, and the pelvis.[63] :16 Unlike human arms, cat forelimbs are attached to the"
                + " shoulder by free-floating clavicle bones which allow them to pass their body through any"
                + " space into which they can fit their head.[64]",
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

        [Fact]
        public void TestHashOutputHashOutput()
        {
            var message1 = Encoding.ASCII.GetBytes("hello");
            var message2 = Encoding.ASCII.GetBytes("how are you good sir?");
            var message3 = Encoding.ASCII.GetBytes("sure thing");

            var h1 = new Hash(32);
            h1.Write(message1);
            h1.Write(message2);
            // this should not affect the state
            h1.Sum();
            h1.Write(message3);

            var out1 = h1.Sum();

            var h2 = new Hash(32);
            h2.Write(message1);
            h2.Write(message2);
            h2.Write(message3);

            var out2 = h2.Sum();

            if (!out1.SequenceEqual(out2))
            {
                throw new Exception("Sum function affects the hash state");
            }
        }

        [Fact]
        public void TestTupleHash()
        {
            var message1 = Encoding.ASCII.GetBytes("the plasma");

            var message2 = Encoding.ASCII.GetBytes("screen is broken, we need to do something about it!");

            var message3 = Encoding.ASCII.GetBytes(
                "\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03"
                + "\x04\x05\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05");

            var message4 = Encoding.ASCII.GetBytes(
                "HAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAH"
                + "AHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHA"
                + "HAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAH"
                + "AHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHA"
                + "HAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHA"
                + "HAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHA" + "HAHAHAHAHAHAHAHAHAHAHAHAHA");

            // trying with NewHash with streaming and without streaming
            var h1 = new Hash(32);

            h1.Write(message1);
            h1.Write(message2);
            h1.Write(message3);
            var out1 = h1.Sum();

            var h2 = new Hash(32);

            h2.WriteTuple(message1);
            h2.WriteTuple(message2);
            h2.WriteTuple(message3);
            var out2 = h2.Sum();

            if (out1.SequenceEqual(out2))
            {
                throw new Exception("Tuple hashing should be different from stream hashing");
            }

            // trying a hybrid with streaming
            var h3 = new Hash(32);

            h3.WriteTuple(message1);
            h3.Write(message2);
            h3.Write(message3);
            h3.WriteTuple(message4);
            var out3 = h3.Sum();

            var h4 = new Hash(32);

            h4.WriteTuple(message1);
            h4.WriteTuple(message2.Concat(message3).ToArray());
            h4.WriteTuple(message4);
            var out4 = h4.Sum();

            if (!out3.SequenceEqual(out4))
            {
                throw new Exception("Tuple hashing doesn't work properly with streaming");
            }
        }
    }
}
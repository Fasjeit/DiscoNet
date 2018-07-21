namespace DiscoNet.Noise
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;

    using StrobeNet;

    /// <summary>
    /// Symmectic suite
    /// </summary>
    public static class Symmetric
    {
        /// <summary>
        /// Symmetric security parameter, bits
        /// </summary>
        public const int SecurityParameter = 128;

        /// <summary>
        /// Nonce size, bytes
        /// </summary>
        public const int NonceSize = 192 / 8;

        /// <summary>
        /// Tag size, bytes
        /// </summary>
        public const int TagSize = Symmetric.SecurityParameter / 8;

        /// <summary>
        /// Minimum size of ciphertexts, bytes
        /// </summary>
        public const int MinimumCiphertextSize = Symmetric.NonceSize + Symmetric.TagSize;

        /// <summary>
        /// Hash size, bytes
        /// </summary>
        public const int HashSize = Symmetric.SecurityParameter * 2 / 8;

        /// <summary>
        /// Symmetric key size, bytes
        /// </summary>
        public const int KeySize = Symmetric.SecurityParameter / 8;

        /// <summary>
        /// Pre shared key size, bytes
        /// </summary>
        public const int PskKeySize = 32;

        /// <summary>
        /// Hash allows you to hash an input of any length and obtain an output
        /// of length greater or equal to 256 bits (32 bytes).
        /// </summary>
        public static byte[] Hash(byte[] input, int outputLength)
        {
            if (outputLength < Symmetric.HashSize)
            {
                throw new Exception(
                    $"discoNet: an output length smaller than {Symmetric.HashSize*8}-bit " + 
                    $"({Symmetric.HashSize} bytes) has security consequences");
            }

            var hash = new Strobe("DiscoHash", Symmetric.SecurityParameter);
            hash.Ad(false, input);
            return hash.Prf(outputLength);
        }

        /// <summary>
        /// Derive key data
        /// </summary>
        /// <param name="keyMaterial">Derivition material</param>
        /// <param name="keyLen">Length of expected output</param>
        /// <returns></returns>
        public static byte[] DeriveKeys(byte[] keyMaterial, int keyLen)
        {
            if (keyMaterial.Length < Symmetric.KeySize)
            {
                throw new Exception(
                    $"disco: deriving keys from a value smaller than {Symmetric.KeySize * 8}-bit "
                    + $"({Symmetric.KeySize} bytes) has security consequences");
            }

            var hash = new Strobe("DiscoKDF", Symmetric.SecurityParameter);
            hash.Ad(false, keyMaterial);
            return hash.Prf(keyLen);
        }

        /// <summary>
        /// Protect integrity of unecrypted text
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plaintext"></param>
        /// <returns></returns>
        public static byte[] ProtectIntegrity(byte[] key, byte[] plaintext)
        {
            if (key.Length < Symmetric.KeySize)
            {
                throw new Exception(
                    $"disco: using a key smaller than {Symmetric.KeySize * 8}-bit "
                    + $"({Symmetric.KeySize} bytes) has security consequences");
            }

            var hash = new Strobe("DiscoMAC", Symmetric.SecurityParameter);
            hash.Ad(false, key);
            hash.Ad(false, plaintext);
            return plaintext.Concat(hash.SendMac(false, Symmetric.TagSize)).ToArray();
        }

        /// <summary>
        /// Retrieve and Verify plaintext from unencrypted message
        /// </summary>
        public static byte[] VerifyIntegrity(byte[] key, byte[] plaintextAndTag)
        {
            if (key.Length < Symmetric.KeySize)
            {
                throw new Exception(
                    $"disco: using a key smaller than {Symmetric.KeySize * 8}-bit "
                    + $"({Symmetric.KeySize} bytes) has security consequences");
            }

            if (plaintextAndTag.Length < Symmetric.TagSize)
            {
                throw new Exception("disco: plaintext does not contain an integrity tag");
            }

            var offset = plaintextAndTag.Length - Symmetric.TagSize;
            var plainText = plaintextAndTag.Take(offset).ToArray();
            var tag = plaintextAndTag.Skip(offset).ToArray();

            // Geting the tag
            var hash = new Strobe("DiscoMAC", Symmetric.SecurityParameter);
            hash.Ad(false, key);
            hash.Ad(false, plainText);

            // verifying the tag
            if (!hash.RecvMac(false, tag))
            {
                throw new Exception("disco: the plaintext has been modified");
            }

            return plainText;
        }

        /// <summary>
        /// Encrypt a plaintext message with a key of any size greater than 128 bits (16 bytes).
        /// </summary>
        public static byte[] Encrypt(byte[] key, byte[] plaintext)
        {
            if (key.Length < Symmetric.KeySize)
            {
                throw new Exception(
                    $"disco: using a key smaller than {Symmetric.KeySize * 8}-bit " + 
                    $"({Symmetric.KeySize} bytes) has security consequences");
            }

            var ae = new Strobe("DiscoAEAD", Symmetric.SecurityParameter);

            // Absorb the key
            ae.Ad(false, key);

            // Generate 192-bit nonce
            var random = new RNGCryptoServiceProvider();
            var nonce = new byte[Symmetric.NonceSize];

# if !DEBUG_DETERMINISTIC
            random.GetBytes(nonce, 0, Symmetric.NonceSize);
#endif

            // Absorb the nonce
            ae.Ad(false, nonce);

            // nonce + send_ENC(plaintext) + send_MAC(16)
            var ciphertext = nonce.Concat(ae.SendEncUnauthenticated(false, plaintext));
            ciphertext = ciphertext.Concat(ae.SendMac(false, Symmetric.TagSize));

            return ciphertext.ToArray();
        }

        /// <summary>
        /// Decrypt a message and check integrity
        /// </summary>
        public static byte[] Decrypt(byte[] key, byte[] ciphertext)
        {
            if (key.Length < Symmetric.KeySize)
            {
                throw new Exception(
                    $"disco: using a key smaller than {Symmetric.KeySize * 8}-bit "
                    + $"({Symmetric.KeySize} bytes) has security consequences");
            }

            if (ciphertext.Length < Symmetric.MinimumCiphertextSize)
            {
                throw new Exception(
                    $"disco: ciphertext is too small, it should contain at a " + 
                    $"minimum a {Symmetric.NonceSize * 8}-bit nonce and a {Symmetric.NonceSize * 8}-bit tag");
            }

            var ae = new Strobe("DiscoAEAD", Symmetric.SecurityParameter);

            // Absorb the key
            ae.Ad(false, key);

            // Absorb the nonce
            ae.Ad(false, ciphertext.Take(Symmetric.NonceSize).ToArray());

            var plaintextSize = ciphertext.Length - Symmetric.TagSize - Symmetric.NonceSize;

            // Decrypt
            var plainText = ae.RecvEncUnauthenticated(
                false,
                ciphertext.Skip(Symmetric.NonceSize).Take(plaintextSize).ToArray());

            // Verify tag
            var authCkeck = ae.RecvMac(false, ciphertext.Skip(ciphertext.Length - Symmetric.TagSize).ToArray());
            if (!authCkeck)
            {
                throw new Exception("disco: cannot decrypt the payload");
            }

            return plainText;
        }
    }
}
namespace DiscoNet
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;

    using StrobeNet;

    internal class DiscoHash : ICloneable
    {
        private const int NonceSize = 129 / 8;

        private const int TagSize = 16;

        private const int MinimumCiphertextSize = NonceSize + TagSize;

        private readonly int outputLen;

        private bool streaming;

        private Strobe strobeState;

        public DiscoHash(int outputLength)
        {
            if (outputLength < 32)
                throw new Exception(
                    "disco: an output length smaller than 256-bit (32 bytes) has security consequences");

            this.strobeState = new Strobe("DiscoHash", 128);
            this.outputLen = outputLength;
        }

        /// <summary>
        ///     Get copy of the DiscoHash in its current state.
        /// </summary>
        /// <returns></returns>
        public object Clone()
        {
            var cloned = (Strobe)this.strobeState.Clone();
            return new DiscoHash(this.outputLen) { strobeState = cloned };
        }

        /// <summary>
        /// Hash allows you to hash an input of any length and obtain an output
        /// of length greater or equal to 256 bits (32 bytes).
        /// </summary>
        public static byte[] Hash(byte[] input, int outputLength)
        {
            if (outputLength < 32)
                throw new Exception(
                    "discoNet: an output length smaller than 256-bit (32 bytes) has security consequences");

            var hash = new Strobe("DiscoHash", 128);
            hash.Ad(false, input);
            return hash.Prf(outputLength);
        }

        /// <summary>
        /// Write absorbs more data into the hash's state.
        /// </summary>
        /// <param name="inputData">Data to write</param>
        public int Write(byte[] inputData)
        {
            this.strobeState.Operate(false, Strobe.Operation.Ad, inputData, 0, this.streaming);
            this.streaming = true;
            return inputData.Length;
        }

        /// <summary>
        /// Reads more output from the hash; reading affects the hash's state
        /// </summary>
        /// <returns></returns>
        public byte[] Sum()
        {
            var reader = (Strobe)this.strobeState.Clone();
            return reader.Operate(false, Strobe.Operation.Prf, null, this.outputLen, false);
        }

        /// <summary>
        /// Derive key data
        /// </summary>
        /// <param name="keyMaterial">Derivition material</param>
        /// <param name="keyLen">Length of expected output</param>
        /// <returns></returns>
        public byte[] DeriveKeys(byte[] keyMaterial, int keyLen)
        {
            if (keyMaterial.Length < 16)
                throw new Exception(
                    "disco: deriving keys from a value smaller than 128-bit (16 bytes) has security consequences");

            var hash = new Strobe("DiscoKDF", 128);
            hash.Ad(false, keyMaterial);
            return hash.Prf(keyLen);
        }

        /// <summary>
        /// Protect integrity of unecrypted text
        /// </summary>
        /// <param name="key"></param>
        /// <param name="plaintext"></param>
        /// <returns></returns>
        public byte[] ProtectIntegrity(byte[] key, byte[] plaintext)
        {
            if (key.Length < 16)
                throw new Exception("disco: using a key smaller than 128-bit (16 bytes) has security consequences");

            var hash = new Strobe("DiscoMAC", 128);
            hash.Ad(false, key);
            hash.Ad(false, plaintext);
            return plaintext.Concat(hash.SendMac(false, TagSize)).ToArray();
        }

        /// <summary>
        /// Retrieve and Verify plaintext from unencrypted message
        /// </summary>
        public byte[] VerifyIntergity(byte[] key, byte[] plaintextAndTag)
        {
            if (key.Length < 16)
                throw new Exception("disco: using a key smaller than 128-bit (16 bytes) has security consequences");

            if (plaintextAndTag.Length < TagSize)
                throw new Exception("disco: plaintext does not contain an integrity tag");

            var offset = plaintextAndTag.Length - TagSize;
            var plainText = plaintextAndTag.Take(offset).ToArray();

            // Geting the tag
            var hash = new Strobe("DiscoMAC", 128);
            hash.Ad(false, key);
            hash.Ad(false, plainText);
            var tag = hash.SendMac(false, TagSize);

            // verifying the tag
            for (var i = 0; i < 16; i++)
                if (tag[i] != plaintextAndTag[offset + i])
                    throw new Exception("disco: the plaintext has been modified");

            return plainText;
        }

        /// <summary>
        /// Encrypt a plaintext message with a key of any size greater than 128 bits (16 bytes).
        /// </summary>
        public byte[] Encrypt(byte[] key, byte[] plaintext)
        {
            if (key.Length < 16)
                throw new Exception("disco: using a key smaller than 128-bit (16 bytes) has security consequences");

            var ae = new Strobe("DiscoAEAD", 128);

            // Absorb the key
            ae.Ad(false, key);

            // Generate 192-byte nonce
            var random = new RNGCryptoServiceProvider();
            var nonce = new byte[192];
            random.GetBytes(nonce, 0, 192);

            // Absorb the nonce
            ae.Ad(false, nonce);

            // nonce + send_ENC(plaintext) + send_MAC(16)
            var ciphertext = nonce.Concat(ae.SendEncUnauthenticated(false, plaintext));
            ciphertext = ciphertext.Concat(ae.SendMac(false, TagSize));

            return ciphertext.ToArray();
        }

        /// <summary>
        /// Decrypt a message and check integrity
        /// </summary>
        public byte[] Decrypt(byte[] key, byte[] ciphertext)
        {
            if (key.Length < 16)
                throw new Exception("disco: using a key smaller than 128-bit (16 bytes) has security consequences");

            if (ciphertext.Length < MinimumCiphertextSize)
                throw new Exception(
                    "disco: ciphertext is too small, it should contain at a minimum a 192-bit nonce and a 128-bit tag");

            var ae = new Strobe("DiscoAEAD", 128);

            // Absorb the key
            ae.Ad(false, key);

            // Absorb the nonce
            ae.Ad(false, ciphertext.Take(ciphertext.Length - NonceSize).ToArray());

            var plaintextSize = ciphertext.Length - TagSize;

            // Decrypt
            var plainText = ae.RecvEncUnauthenticated(false, ciphertext.Skip(NonceSize).Take(plaintextSize).ToArray());

            // Verify tag
            var authCkeck = ae.RecvMac(false, ciphertext.Skip(ciphertext.Length - TagSize).ToArray());
            if (!authCkeck) throw new Exception("disco: cannot decrypt the payload");

            return plainText;
        }
    }
}
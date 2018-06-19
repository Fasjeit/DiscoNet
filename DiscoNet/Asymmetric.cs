using System;
using System.Security.Cryptography;
using Sodium;

namespace DiscoNet
{
    // The following code defines the X25519, chacha20poly1305, SHA-256 suite.

    class Asymmetric
    {
        /// <summary>
        /// A constant specifying the size in bytes of public keys and DH outputs.
        /// </summary>
        /// <remarks>
        /// For security reasons, dhLen must be 32 or greater.
        /// </remarks>
        const int DhLen = 32;

        // 4.1. DH functions

        public class KeyPair
        {
            public byte[] PrivateKey { get; set; } = new byte[32];
            public byte[] PublicKey { get; set; } = new byte[32];

            public string ExportPublicKey()
            {
                return BitConverter.ToString(PublicKey).Replace("-", string.Empty);
            }
        }

        /// <summary>
        /// GenerateKeypair creates a X25519 static keyPair out of a private key. 
        /// If privateKey is null the function generates a random key pair.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public KeyPair GenerateKeyPair(byte[] privateKey)
        {
            //#Q_ source + check if 32 bytes
            var keyPair = new KeyPair();
            if (privateKey != null)
            {
                keyPair.PrivateKey = privateKey;
            }
            else
            {
                var random = new RNGCryptoServiceProvider();
                random.GetBytes(keyPair.PrivateKey, 0, keyPair.PrivateKey.Length);
            }
            keyPair.PublicKey = ScalarMult.Base(keyPair.PrivateKey);

            return keyPair;
        }

        public byte[] Dh(KeyPair keyPair, byte[] publicKey)
        {
            //#Q_ source - shared [32]byte ???
            return ScalarMult.Mult(keyPair.PrivateKey, publicKey);
        }
    }
}

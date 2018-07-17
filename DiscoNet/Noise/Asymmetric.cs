namespace DiscoNet.Noise
{
    using System;
    using System.Security.Cryptography;

    using Sodium;

    using KeyPair = DiscoNet.KeyPair;

    // The following code defines the X25519, chacha20poly1305, SHA-256 suite.

    public class Asymmetric
    {
        /// <summary>
        /// A constant specifying the size in bytes of public keys and DH outputs.
        /// </summary>
        /// <remarks>
        /// For security reasons, dhLen must be 32 or greater.
        /// </remarks>
        public const int DhLen = 32;

        // 4.1. DH functions

        /// <summary>
        /// GenerateKeypair creates a X25519 static keyPair out of a private key. 
        /// If privateKey is null the function generates a random key pair.
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static KeyPair GenerateKeyPair(byte[] privateKey = null)
        {
            var keyPair = new KeyPair();

            if (privateKey == null)
            {
                var random = new RNGCryptoServiceProvider();
                random.GetBytes(keyPair.PrivateKey, 0, keyPair.PrivateKey.Length);
            }
            else
            {
                if (privateKey.Length != 32)
                {
                    throw new Exception("disco: expecting 32 byte key array");
                }
                privateKey.CopyTo(keyPair.PrivateKey, 0);
            }

            keyPair.PublicKey = ScalarMult.Base(keyPair.PrivateKey);

            return keyPair;
        }
        
        /// <summary>
        /// Perform DH on public key
        /// </summary>
        /// <param name="keyPair"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static byte[] Dh(KeyPair keyPair, byte[] publicKey)
        {
            return ScalarMult.Mult(keyPair.PrivateKey, publicKey);
        }
    }
}

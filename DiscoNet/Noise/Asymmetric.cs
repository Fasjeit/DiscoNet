namespace DiscoNet.Noise
{
    using System;
    using System.Security.Cryptography;

    using Sodium;

    using KeyPair = DiscoNet.KeyPair;

    /// <summary>
    /// Asymmetric suite
    /// </summary>
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
        /// Create a X25519 static keyPair out of a private key.
        /// </summary>
        /// <param name="privateKey">Private key, if null - generates a random key pair</param>
        public static KeyPair GenerateKeyPair(byte[] privateKey = null)
        {
            var keyPair = new KeyPair() {
                PublicKey = new byte[32],
                PrivateKey = new byte[32]
            };

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
        /// <param name="keyPair">Containing private key</param>
        /// <param name="publicKey">Remoe party's public key</param>
        /// <returns></returns>
        public static byte[] Dh(KeyPair keyPair, byte[] publicKey)
        {
            return ScalarMult.Mult(keyPair.PrivateKey, publicKey);
        }
    }
}
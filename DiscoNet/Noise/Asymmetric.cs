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
        /// <returns>X25519 key pair</returns>
        public static KeyPair GenerateKeyPair(byte[] privateKey = null)
        {
            var keyPair = new KeyPair() {
                PublicKey = new byte[Asymmetric.DhLen],
                PrivateKey = new byte[Asymmetric.DhLen]
            };

            if (privateKey == null)
            {
                var random = new RNGCryptoServiceProvider();
#if !DEBUG_DETERMINISTIC
                random.GetBytes(keyPair.PrivateKey, 0, keyPair.PrivateKey.Length);
#endif
            }
            else
            {
                if (privateKey.Length != Asymmetric.DhLen)
                {
                    throw new Exception($"disco: expecting {Asymmetric.DhLen} byte key array");
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
        /// <param name="publicKey">Remote party's public key</param>
        /// <returns>DH result</returns>
        public static byte[] Dh(KeyPair keyPair, byte[] publicKey)
        {
            return ScalarMult.Mult(keyPair.PrivateKey, publicKey);
        }
    }
}
namespace DiscoNet
{
    using System;

    using StrobeNet.Extensions;

    /// <summary>
    /// Asymmectic x25519 keypair
    /// </summary>
    public class KeyPair : IDisposable
    {
        /// <summary>
        /// Private key
        /// </summary>
        public byte[] PrivateKey { get; set; }

        /// <summary>
        /// Public key
        /// </summary>
        public byte[] PublicKey { get; set; }

        /// <summary>
        /// Dispose object and free resourses
        /// </summary>
        public void Dispose()
        {
            if (this.PrivateKey != null)
            {
                Array.Clear(this.PrivateKey, 0, this.PrivateKey.Length);
            }
        }

        /// <summary>
        /// Export public key as hex string
        /// </summary>
        /// <returns></returns>
        public string ExportPublicKey()
        {
            return this.PublicKey.ToHexString();
        }

        /// <summary>
        /// Export private key as hex string
        /// </summary>
        /// <returns></returns>
        internal string ExportPrivateKey()
        {
            return this.PrivateKey.ToHexString();
        }

        /// <summary>
        /// Import public key from hex string
        /// </summary>
        /// <param name="hex"></param>
        public void ImportPublicKey(string hex)
        {
            this.PublicKey = hex.ToByteArray();
        }

        /// <summary>
        /// Import private key as hex string
        /// </summary>
        /// <param name="hex"></param>
        internal void ImportPrivateKey(string hex)
        {
            this.PrivateKey = hex.ToByteArray();
        }

        ~KeyPair()
        {
            this.Dispose();
        }
    }
}
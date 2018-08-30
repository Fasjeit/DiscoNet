namespace DiscoNet
{
    using System;

    using StrobeNet.Extensions;

    /// <summary>
    /// Asymmetric x25519 key pair
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
        /// Dispose object and free resources
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
        /// <returns>String representation of public key</returns>
        public string ExportPublicKey()
        {
            return this.PublicKey.ToHexString();
        }

        /// <summary>
        /// Export private key as hex string
        /// </summary>
        /// <returns>String representation of private key</returns>
        internal string ExportPrivateKey()
        {
            return this.PrivateKey.ToHexString();
        }

        /// <summary>
        /// Import public key from hex string
        /// </summary>
        /// <param name="hex">String representation of public key</param>
        public void ImportPublicKey(string hex)
        {
            this.PublicKey = hex.ToByteArray();
        }

        /// <summary>
        /// Import private key as hex string
        /// </summary>
        /// <param name="hex">String representation of private key</param>
        internal void ImportPrivateKey(string hex)
        {
            this.PrivateKey = hex.ToByteArray();
        }

        /// <summary>
        /// Destructor
        /// </summary>
        ~KeyPair()
        {
            this.Dispose();
        }
    }
}
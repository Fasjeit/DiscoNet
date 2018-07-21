namespace DiscoNet
{
    using System;

    using StrobeNet.Extensions;

    /// <summary>
    /// Asymmectic x25519 keypair
    /// </summary>
    public class KeyPair : IDisposable
    {
        public byte[] PrivateKey { get; set; }

        public byte[] PublicKey { get; set; }

        public void Dispose()
        {
            if (this.PrivateKey != null)
            {
                Array.Clear(this.PrivateKey, 0, this.PrivateKey.Length);
            }
        }

        public string ExportPublicKey()
        {
            return this.PublicKey.ToHexString();
        }

        internal string ExportPrivateKey()
        {
            return this.PrivateKey.ToHexString();
        }

        public void ImportPublicKey(string hex)
        {
            this.PublicKey = hex.ToByteArray();
        }

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
namespace DiscoNet
{
    using System;
    using System.Linq;
    using StrobeNet.Extensions;

    public class KeyPair : IDisposable
    {
        public byte[] PrivateKey { get; set; } = new byte[32];
        public byte[] PublicKey { get; set; } = new byte[32];

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

        public void Dispose()
        {
            Array.Clear(this.PrivateKey, 0, this.PrivateKey.Length);
        }

        ~KeyPair()
        {
            this.Dispose();
        }
    }
}

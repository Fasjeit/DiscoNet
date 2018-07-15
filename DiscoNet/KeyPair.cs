namespace DiscoNet
{
    using System;

    public class KeyPair : IDisposable
    {
        public byte[] PrivateKey { get; set; } = new byte[32];
        public byte[] PublicKey { get; set; } = new byte[32];

        public string ExportPublicKey()
        {
            return BitConverter.ToString(this.PublicKey).Replace("-", string.Empty);
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

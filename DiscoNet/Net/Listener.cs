namespace DiscoNet.Disco
{
    using System;
    using System.Net;
    using System.Net.Sockets;

    using DiscoNet.Noise.Enums;

    public class Listener
    {
        Config config;
        TcpListener listener;

        public Listener(string address, int port, Config config)
        {
            this.config = config ?? throw new ArgumentNullException(nameof(config));
            this.CheckRequirments(false);

            this.listener = new TcpListener(IPAddress.Parse(address), port);
        }

        public Socket Accept()
        {
            return this.listener.AcceptSocket();
        }

        private void CheckRequirments(bool isClient)
        {
            var ht = this.config.HandshakePattern;
            if (ht == NoiseHandshakeType.NoiseNX ||
                ht == NoiseHandshakeType.NoiseKX ||
                ht == NoiseHandshakeType.NoiseXX ||
                ht == NoiseHandshakeType.NoiseIX)
            {
                if (isClient && this.config.PublicKeyVerifier == null)
                {
                    throw new Exception("Disco: no public key verifier set in Config");
                }
                if (!isClient && this.config.StaticPublicKeyProof == null)
                {
                    throw new Exception("Disco: no public key proof set in Config");
                }
            }

            if (ht == NoiseHandshakeType.NoiseXN ||
                ht == NoiseHandshakeType.NoiseXK ||
                ht == NoiseHandshakeType.NoiseXX ||
                ht == NoiseHandshakeType.NoiseX ||
                ht == NoiseHandshakeType.NoiseIN ||
                ht == NoiseHandshakeType.NoiseIK ||
                ht == NoiseHandshakeType.NoiseIX)
            {
                if (isClient && this.config.StaticPublicKeyProof == null)
                {
                    throw new Exception("Disco: no public key proof set in Config");
                }

                if (!isClient && this.config.PublicKeyVerifier == null)
                {
                    throw new Exception("Disco: no public key verifier set in Config");
                }
            }

            if (ht == NoiseHandshakeType.NoiseNNpsk2 && this.config.PreSharedKey.Length != 32)
            {
                throw new Exception("noise: a 32-byte pre-shared key needs to be passed as noise.Config");
            }
        }
    }
}

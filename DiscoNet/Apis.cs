namespace DiscoNet
{
    using System;
    using System.Net;
    using System.Net.Sockets;

    internal class Apis
    {
    }

    internal class Listener
    {
        Config config;
        TcpListener listener;

        public Listener(string address, int port, Config config)
        {
            this.config = config ?? throw new ArgumentNullException(nameof(config));
            this.CheckRequirments(false);

            this.listener = new TcpListener(IPAddress.Parse(address), port);
        }


        /// <summary>
        /// Server returns a new Disco server side connection
        /// using net.Conn as the underlying transport.
        /// The configuration config must be non-nil and must include
        /// at least one certificate or else set GetCertificate.
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="config"></param>
        /// <returns></returns>
        private Connection Server(Socket connection, Config config)
        {
            return new Connection() { SocketConnection = connection, config = config, };
        }

        /// <summary>
        ///  Client returns a new Disco client side connection
        /// using conn as the underlying transport.
        /// The config cannot be nil: users must set either ServerName or
        /// InsecureSkipVerify in the config.
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="config"></param>
        /// <returns></returns>
        private Connection Client(Socket connection, Config config)
        {
            return new Connection() { SocketConnection = connection, config = config, IsClient = true };
        }

        public void Accept()
        {
            this.listener.AcceptSocket();
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
                if(!isClient && this.config.StaticPublicKeyProof == null)
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
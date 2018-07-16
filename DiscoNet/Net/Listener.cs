namespace DiscoNet.Disco
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using DiscoNet.Net;
    using DiscoNet.Noise.Enums;

    public class Listener
    {
        const int MaxConnecions = 1;

        Config config;
        TcpListener listener;

        const int MaxConnections = 1;


        /// <summary>
        /// Server returns a new Disco server side connection
        /// using net.Conn as the underlying transport.
        /// The configuration config must be non-nil and must include
        /// at least one certificate or else set GetCertificate.
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="config"></param>
        /// <returns></returns>
        private Connection Server(TcpClient connection, Config config)
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
        private static Connection Client(TcpClient connection, Config config)
        {
            return new Connection() { SocketConnection = connection, config = config, IsClient = true };
        }

        public static Connection DialWithDialer(string network, string addr, int port, Config config)
        {
            if (config == null)
            {
                throw new NullReferenceException(nameof(config));
            }

            CheckRequirments(false, config);

            //var ipAddress = IPAddress.Parse(addr);
            //IPEndPoint localEndPoint = new IPEndPoint(ipAddress, port);

            //var rawConn = new TcpListener(ipAddress, port);
            //rawConn.Start();

            var tcpClient = new TcpClient(addr, port);

            var connection = Client(tcpClient, config);

            // Do the handshake
            connection.HandShake();

            return connection;
        }

        internal static void CheckRequirments(bool isClient, Config config)
        {
            var ht = config.HandshakePattern;
            if (ht == NoiseHandshakeType.NoiseNX ||
                ht == NoiseHandshakeType.NoiseKX ||
                ht == NoiseHandshakeType.NoiseXX ||
                ht == NoiseHandshakeType.NoiseIX)
            {
                if (isClient && config.PublicKeyVerifier == null)
                {
                    throw new Exception("Disco: no public key verifier set in Config");
                }
                if (!isClient && config.StaticPublicKeyProof == null)
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
                if (isClient && config.StaticPublicKeyProof == null)
                {
                    throw new Exception("Disco: no public key proof set in Config");
                }

                if (!isClient && config.PublicKeyVerifier == null)
                {
                    throw new Exception("Disco: no public key verifier set in Config");
                }
            }

            if (ht == NoiseHandshakeType.NoiseNNpsk2 && config.PreSharedKey.Length != 32)
            {
                throw new Exception("noise: a 32-byte pre-shared key needs to be passed as noise.Config");
            }
        }

        public Listener(string address, Config config, int port = 1800)
        {
            this.config = config ?? throw new ArgumentNullException(nameof(config));
            CheckRequirments(false, this.config);

            var iPAddress = IPAddress.Parse(address);
            //var localEndPoint = new IPEndPoint(iPAddress, port);

            this.listener = new TcpListener(iPAddress, port);

            // #Q_ ToDo - dispose and stop!!!
            this.listener.Start();
        }

        public Connection Accept()
        {
            var tcpClient = this.listener.AcceptTcpClient();
            return Server(tcpClient, this.config);
        }        
    }
}

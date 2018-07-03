namespace DiscoNet
{
    using System;
    using System.Net;
    using System.Net.Sockets;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    internal class Apis
    {
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

        public bool Dial(string netwrk, string address, Config config)
        {
            throw new NotImplementedException();
        }

        internal Connection DialWithDialer(Socket dialer, string network, string addr, Config config)
        {
            if (config == null)
            {
                throw new NullReferenceException(nameof(config));
            }

            //var rawConn = dialer.Connect(network, addr);

            //var conn = Client(rawConn, config);
            //conn.HandshakeState = 
            throw new NotImplementedException();
        }
    }
}
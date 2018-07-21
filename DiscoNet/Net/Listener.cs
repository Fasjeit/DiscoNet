namespace DiscoNet.Net
{
    using System;
    using System.Net;
    using System.Net.Sockets;

    public class Listener : IDisposable
    {
        private bool isListening;

        private readonly Config config;

        private readonly TcpListener tcpListener;

        /// <summary>
        /// Create disco listener
        /// </summary>
        /// <param name="address"></param>
        /// <param name="config"></param>
        /// <param name="port"></param>
        internal Listener(string address, Config config, int port = 1800)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            Apis.CheckRequirments(false, config);

            var iPAddress = IPAddress.Parse(address);

            this.config = config;
            this.tcpListener = new TcpListener(iPAddress, port);
        }

        public void Dispose()
        {
            this.tcpListener.Stop();
        }

        /// <summary>
        /// Accept disco connection
        /// </summary>
        /// <returns></returns>
        public Connection Accept()
        {
            if (!this.isListening)
            {
                throw new InvalidOperationException("Listenes should be started to Accept connections");
            }

            var tcpClient = this.tcpListener.AcceptTcpClient();
            return Apis.Server(tcpClient, this.config);
        }

        /// <summary>
        /// Start listening for clients
        /// </summary>
        public void Start()
        {
            if (this.tcpListener == null)
            {
                throw new ArgumentNullException(nameof(this.tcpListener));
            }

            this.tcpListener.Start();
            this.isListening = true;
        }

        /// <summary>
        /// Stop listening for clients
        /// </summary>
        public void Stop()
        {
            if (this.tcpListener == null)
            {
                return;
            }

            this.tcpListener.Stop();
            this.isListening = false;
        }
    }
}
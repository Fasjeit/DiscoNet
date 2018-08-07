namespace DiscoNet.Net
{
    using System;
    using System.Net;
    using System.Net.Sockets;

    /// <summary>
    /// Disco Listener
    /// </summary>
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
        internal Listener(IPAddress address, Config config, int port = 1800)
        {
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            Api.CheckRequirments(false, config);

            this.config = config;
            this.tcpListener = new TcpListener(address, port);
        }

        /// <summary>
        /// Create disco listener
        /// </summary>
        /// <param name="address"></param>
        /// <param name="config"></param>
        /// <param name="port"></param>
        internal Listener(string address, Config config, int port = 1800)
            : this(IPAddress.Parse(address), config, port)
        {

        }

        /// <summary>
        /// Dispose connection
        /// </summary>
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
            return Api.Server(tcpClient, this.config);
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
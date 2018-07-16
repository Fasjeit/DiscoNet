namespace DiscoNet.Disco
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using DiscoNet.Net;

    public class Listener : IDisposable
    {
        private bool isListening;

        public Config config { get; internal set; }
        public TcpListener tcpListener { get; internal set; }

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

        public Connection Accept()
        {
            if (!this.isListening)
            {
                throw new InvalidOperationException("Listenes should be started to Accept connections");
            }
            var tcpClient = this.tcpListener.AcceptTcpClient();
            return Apis.Server(tcpClient, this.config);
        }

        public void Start()
        {
            if (this.tcpListener == null)
            {
                throw new ArgumentNullException(nameof(this.tcpListener));
            }
            this.tcpListener.Start();
            this.isListening = true;
        }

        public void Stop()
        {
            if (this.tcpListener != null)
            {
                this.tcpListener.Stop();
                this.isListening = false;
            }
        }

        public void Dispose()
        {
            this.tcpListener.Stop();
        }
    }
}

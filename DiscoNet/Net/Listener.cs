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

        public Listener(string address, Config config, int port = 1800)
        {
            this.config = config ?? throw new ArgumentNullException(nameof(config));
            Apis.CheckRequirments(false, this.config);

            var iPAddress = IPAddress.Parse(address);
            //var localEndPoint = new IPEndPoint(iPAddress, port);

            this.listener = new TcpListener(iPAddress, port);

            // #Q_ ToDo - dispose and stop!!!
            this.listener.Start();
        }

        public TcpClient Accept()
        {
            return this.listener.AcceptTcpClient();
        }        
    }
}

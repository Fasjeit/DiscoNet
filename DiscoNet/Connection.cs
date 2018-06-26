namespace DiscoNet
{
    using System.Net.Sockets;

    internal class Connection
    {
        public Socket SocketConnection { get; set; }

        public bool IsClient { get; set; }

        public Config config { get; set; }

        //HandshakeState
    }
}

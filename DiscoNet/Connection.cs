namespace DiscoNet
{
    using System.Net.Sockets;
    using System.Threading;

    using DiscoNet.Noise;

    using StrobeNet;

    /// <summary>
    /// Represents a secured connection
    /// </summary>
    internal class Connection
    {
        public Socket SocketConnection { get; set; }

        public bool IsClient { get; set; }

        //HandshakeState
        public Config config { get; set; }
        private HandshakeState HandshakeState { get; set; }

        private bool handshakeComplite { get; set; }

        private Mutex handshakeMutex { get; set; }

        // Authentication thingies
        private bool isRemoteAuthenticated { get; set; }

        // input/output
        private Strobe strobeIn { get; set; }

        private Strobe strobeOut { get; set; }

        private byte[] inputBuffer { get; set; }

        // half duplex
        private bool isHalfDuplex { get; set; }

        private Mutex halfDuplexLock { get; set; }
    }
}

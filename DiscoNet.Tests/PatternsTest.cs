namespace DiscoNet.Tests
{
    using System;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using DiscoNet.Disco;
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;
    using Xunit;

    public class PatternsTest
    {
        [Fact]
        public void TestNoiseKk()
        {
            RunTwoWayTest(NoiseHandshakeType.NoiseKK);
        }

        [Fact]
        public void TestNoiseNk()
        {
            RunTwoWayTest(NoiseHandshakeType.NoiseNK);
        }

        [Fact]
        public void TestNoiseXx()
        {
            RunTwoWayTest(NoiseHandshakeType.NoiseXX);
        }

        [Fact]
        public void TestNoiseN()
        {
            //RunTwoWayTest(NoiseHandshakeType.NoiseN);
        }

        private void RunTwoWayTest(NoiseHandshakeType pattern)
        {
            // init
            var clientConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = pattern
            };

            var serverConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = pattern
            };

            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;

            var address = "127.0.0.1";

            // get a Noise.listener
            var listener = new Listener(address, serverConfig, 1800);

            // run the server and Accept one connection

            Task.Factory.StartNew(() =>
            {
                var serverSocket = listener.Accept();
                var buf = new byte[100];
                var n = serverSocket.Read(buf);
                if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                {
                    throw new System.Exception("client message failed");
                }

                serverSocket.Write(Encoding.ASCII.GetBytes("ca va?"));
            });

            // Run the client
            var clientSocket = Listener.DialWithDialer("tcp", address, 1800, clientConfig);

            clientSocket.Write(Encoding.ASCII.GetBytes("hello"));

            var bufClient = new byte[100];
            var readByes = clientSocket.Read(bufClient);

            if (!bufClient.Take(readByes).SequenceEqual(Encoding.ASCII.GetBytes("ca va?")))
            {
                throw new Exception();
            }
        }
    }
}


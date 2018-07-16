namespace DiscoNet.Tests
{
    using System;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using DiscoNet.Disco;
    using DiscoNet.Net;
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;
    using Xunit;

    public class PatternsTest
    {
        [Fact]
        public void TestNoiseKk()
        {
            // init
            var clientConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseKK
            };

            var serverConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseKK
            };

            RunTwoWayTest(clientConfig, serverConfig);
        }

        [Fact]
        public void TestNoiseNk()
        {
            // init
            var clientConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseNK
            };

            var serverConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseNK
            };

            RunTwoWayTest(clientConfig, serverConfig);
        }

        [Fact]
        public void TestNoiseXx()
        {
            throw new NotImplementedException();
        }

        [Fact]
        public void TestNoiseN()
        {
            throw new NotImplementedException();
        }

        private void RunTwoWayTest(Config clientConfig, Config serverConfig)
        {


            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;

            var address = "127.0.0.1";

            // get a Noise.listener
           
                // run the server and Accept one connection

                Task.Factory.StartNew(() =>
                {
                    using (var listener = Apis.Listen(address, serverConfig, 1800))
                    {
                        var serverSocket = listener.Accept();
                        var buf = new byte[100];
                        var n = serverSocket.Read(buf);
                        if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                        {
                            throw new Exception("client message failed");
                        }

                        serverSocket.Write(Encoding.ASCII.GetBytes("ca va?"));
                    }
                });

            // Run the client
            var clientSocket = Apis.Connect("tcp", address, 1800, clientConfig);

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


namespace DiscoNet.Tests
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    using DiscoNet.Net;
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    using Sodium;

    using Xunit;

    public class PatternsTest
    {
        [Fact]
        public void TestNoiseKk()
        {
            // init
            var clientConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseKK
            };

            var serverConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseKK
            };

            this.RunTwoWayTest(clientConfig, serverConfig, 1800);
        }

        [Fact]
        public void TestNoiseNk()
        {
            // init
            var clientConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseNK
            };

            var serverConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseNK
            };

            this.RunTwoWayTest(clientConfig, serverConfig, 1801);
        }

        [Fact]
        public void TestNoiseXx()
        {
            var rootKey = PublicKeyAuth.GenerateKeyPair();
            var Verifier = Api.CreatePublicKeyVerifier(rootKey.PublicKey);

            var clienPair = Asymmetric.GenerateKeyPair();
            var serverPair = Asymmetric.GenerateKeyPair();

            // init
            var clientConfig = new Config
            {
                KeyPair = clienPair,
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = Verifier,
                StaticPublicKeyProof = Api.CreateStaticPublicKeyProof(rootKey.PrivateKey, clienPair.PublicKey)
            };

            var serverConfig = new Config
            {
                KeyPair = serverPair,
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = Verifier,
                StaticPublicKeyProof = Api.CreateStaticPublicKeyProof(rootKey.PrivateKey, serverPair.PublicKey)
            };

            this.RunTwoWayTest(clientConfig, serverConfig, 1802);
        }

        [Fact]
        public void TestNoiseN()
        {
            // init
            var clientConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseN
            };

            var serverConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseN
            };

            this.RunOneWayTest(clientConfig, serverConfig, 1803);
        }

        private void RunOneWayTest(Config clientConfig, Config serverConfig, int port = 1800)
        {
            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;

            var address = IPAddress.Loopback;

            var serverSetUp = false;

            Task.Factory.StartNew(
                () =>
                    {
                        using (var listener = Api.Listen(address, serverConfig, port))
                        {
                            serverSetUp = true;
                            var serverSocket = listener.Accept();
                            var buf = new byte[100];
                            var n = serverSocket.Read(buf, 0, buf.Length);

                            if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                            {
                                throw new Exception("client message failed");
                            }

                            // Expect error in here
                            try
                            {
                                var data = Encoding.ASCII.GetBytes("ca va?");
                                serverSocket.Write(data, 0, data.Length);
                            }
                            catch (Exception ex)
                            {
                                if (ex.Message != "disco: a server should not write on one-way patterns")
                                {
                                    throw new Exception($"Unexpected Server Exception: {ex}");
                                }

                                return;
                            }

                            throw new Exception("Server should not write in one way pattern");
                        }
                    });

            while (!serverSetUp)
            {
                Thread.Sleep(1000);
            }

            // Run the client
            var clientSocket = Api.Connect(address.ToString(), port, clientConfig);

            var cleintData = Encoding.ASCII.GetBytes("hello");
            clientSocket.Write(cleintData, 0, cleintData.Length);
        }

        private void RunTwoWayTest(Config clientConfig, Config serverConfig, int port = 1800)
        {
            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;

            var address = IPAddress.Loopback;

            var serverSetUp = false;

            // get a Noise.listener

            // run the server and Accept one connection

            Task.Factory.StartNew(
                () =>
                    {
                        using (var listener = Api.Listen(address, serverConfig, port))
                        {
                            serverSetUp = true;
                            var serverSocket = listener.Accept();
                            var buf = new byte[100];
                            var n = serverSocket.Read(buf, 0, buf.Length);

                            if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                            {
                                throw new Exception("client message failed");
                            }

                            var data = Encoding.ASCII.GetBytes("ca va?");
                            serverSocket.Write(data, 0, data.Length);
                        }
                    });

            while (!serverSetUp)
            {
                Thread.Sleep(1000);
            }

            // Run the client
            var clientSocket = Api.Connect(address.ToString(), port, clientConfig);

            var clienData = Encoding.ASCII.GetBytes("hello");
            clientSocket.Write(clienData, 0, clienData.Length);

            var bufClient = new byte[100];
            var readByes = clientSocket.Read(bufClient, 0, bufClient.Length);

            if (!bufClient.Take(readByes).SequenceEqual(Encoding.ASCII.GetBytes("ca va?")))
            {
                throw new Exception();
            }
        }
    }
}
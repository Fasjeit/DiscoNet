namespace DiscoNet.Tests
{
    using System;
    using System.Linq;
    using System.Text;
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

            var address = "127.0.0.1";

            Task.Factory.StartNew(
                () =>
                    {
                        using (var listener = Api.Listen(address, serverConfig, port))
                        {
                            var serverSocket = listener.Accept();
                            var buf = new byte[100];
                            var n = serverSocket.Read(buf, out var exception);
                            if (exception != null)
                            {
                                throw exception;
                            }
                            if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                            {
                                throw new Exception("client message failed");
                            }

                            // Expect error in here
                            try
                            {
                                serverSocket.Write(Encoding.ASCII.GetBytes("ca va?"), out exception);
                                if (exception != null)
                                {
                                    throw exception;
                                }
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

            // Run the client
            var clientSocket = Api.Connect(address, port, clientConfig);

            clientSocket.Write(Encoding.ASCII.GetBytes("hello"), out var clientException);
            if (clientException != null)
            {
                throw clientException;
            }
        }

        private void RunTwoWayTest(Config clientConfig, Config serverConfig, int port = 1800)
        {
            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;

            var address = "127.0.0.1";

            // get a Noise.listener

            // run the server and Accept one connection

            Task.Factory.StartNew(
                () =>
                    {
                        using (var listener = Api.Listen(address, serverConfig, port))
                        {
                            var serverSocket = listener.Accept();
                            var buf = new byte[100];
                            var n = serverSocket.Read(buf, out var exception);
                            if (exception != null)
                            {
                                throw exception;
                            }
                            if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                            {
                                throw new Exception("client message failed");
                            }

                            serverSocket.Write(Encoding.ASCII.GetBytes("ca va?"), out exception);
                            if (exception != null)
                            {
                                throw exception;
                            }
                        }
                    });

            // Run the client
            var clientSocket = Api.Connect(address, port, clientConfig);

            clientSocket.Write(Encoding.ASCII.GetBytes("hello"), out var clientException);
            if (clientException != null)
            {
                throw clientException;
            }
            var bufClient = new byte[100];
            var readByes = clientSocket.Read(bufClient, out clientException);
            if (clientException != null)
            {
                throw clientException;
            }

            if (!bufClient.Take(readByes).SequenceEqual(Encoding.ASCII.GetBytes("ca va?")))
            {
                throw new Exception();
            }
        }
    }
}
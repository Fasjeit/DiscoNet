namespace DiscoNet.Tests
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
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
            var Verifier = DiscoHelper.CreatePublicKeyVerifier(rootKey.PublicKey);

            var clienPair = Asymmetric.GenerateKeyPair();
            var serverPair = Asymmetric.GenerateKeyPair();

            // init
            var clientConfig = new Config
            {
                KeyPair = clienPair,
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = Verifier,
                StaticPublicKeyProof = DiscoHelper.CreateStaticPublicKeyProof(rootKey.PrivateKey, clienPair.PublicKey)
            };

            var serverConfig = new Config
            {
                KeyPair = serverPair,
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = Verifier,
                StaticPublicKeyProof = DiscoHelper.CreateStaticPublicKeyProof(rootKey.PrivateKey, serverPair.PublicKey)
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
                    var listener = new TcpListener(address, port);
                    listener.Start();
                    serverSetUp = true;
                    using (var clinet = listener.AcceptTcpClient())
                    {
                        using (var serverConnection = new Connection(clinet.GetStream()))
                        {

                            serverConnection.AuthenticateAsServer(serverConfig);
                            var buf = new byte[100];
                            var n = serverConnection.Read(buf, 0, buf.Length);

                            if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                            {
                                throw new Exception("client message failed");
                            }

                            // Expect error in here
                            try
                            {
                                var data = Encoding.ASCII.GetBytes("ca va?");
                                serverConnection.Write(data, 0, data.Length);
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
                    }

                    listener.Stop();
                });

            while (!serverSetUp)
            {
                Thread.Sleep(1000);
            }

            // Run the client
            using (var clientSocket = new TcpClient(address.ToString(), port))
            {
                using (var clinetConnection = new Connection(clientSocket.GetStream()))
                {
                    clinetConnection.AuthenticateAsClient(clientConfig);
                    var cleintData = Encoding.ASCII.GetBytes("hello");
                    clinetConnection.Write(cleintData, 0, cleintData.Length);
                }
            }
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
                        var listener = new TcpListener(address, port);
                        listener.Start();
                        serverSetUp = true;
                        using (var clinet = listener.AcceptTcpClient())
                        {
                            using (var serverConnection = new Connection(clinet.GetStream()))
                            {
                                serverConnection.AuthenticateAsServer(serverConfig);
                                serverSetUp = true;
                                var buf = new byte[100];
                                var n = serverConnection.Read(buf, 0, buf.Length);

                                if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                                {
                                    throw new Exception("client message failed");
                                }

                                var data = Encoding.ASCII.GetBytes("ca va?");
                                serverConnection.Write(data, 0, data.Length);
                            }
                        }

                        listener.Stop();
                    });

            while (!serverSetUp)
            {
                Thread.Sleep(1000);
            }

            // Run the client
            // Run the client
            using (var clientSocket = new TcpClient(address.ToString(), port))
            {
                using (var clinetConnection = new Connection(clientSocket.GetStream()))
                {
                    clinetConnection.AuthenticateAsClient(clientConfig);
                    var clienData = Encoding.ASCII.GetBytes("hello");
                    clinetConnection.Write(clienData, 0, clienData.Length);

                    var bufClient = new byte[100];
                    var readByes = clinetConnection.Read(bufClient, 0, bufClient.Length);

                    if (!bufClient.Take(readByes).SequenceEqual(Encoding.ASCII.GetBytes("ca va?")))
                    {
                        throw new Exception();
                    }
                }
            }
        }
    }
}
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

            RunTwoWayTest(clientConfig, serverConfig, 1800);
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

            RunTwoWayTest(clientConfig, serverConfig, 1801);
        }

        [Fact]
        public void TestNoiseXx()
        {
            Sodium.KeyPair rootKey = Sodium.PublicKeyAuth.GenerateKeyPair();
            Config.PublicKeyVerifierDeligate Verifier = Apis.CreatePublicKeyVerifier(rootKey.PublicKey);

            var clienPair = Asymmetric.GenerateKeyPair();
            var serverPair = Asymmetric.GenerateKeyPair();

            // init
            var clientConfig = new Config()
            {
                KeyPair = clienPair,
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = Verifier,
                StaticPublicKeyProof = Apis.CreateStaticPublicKeyProof(rootKey.PrivateKey, clienPair.PublicKey)
            };

            var serverConfig = new Config()
            {
                KeyPair = serverPair,
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = Verifier,
                StaticPublicKeyProof = Apis.CreateStaticPublicKeyProof(rootKey.PrivateKey, serverPair.PublicKey)
            };

            RunTwoWayTest(clientConfig, serverConfig, 1802);
        }

        [Fact]
        public void TestNoiseN()
        {
            // init
            var clientConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseN
            };

            var serverConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseN
            };

            RunOneWayTest(clientConfig, serverConfig, 1803);
        }

        private void RunOneWayTest(Config clientConfig, Config serverConfig, int port = 1800)
        {
            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;

            var address = "127.0.0.1";

            Task.Factory.StartNew(() =>
            {
                using (var listener = Apis.Listen(address, serverConfig, port))
                {
                    var serverSocket = listener.Accept();
                    var buf = new byte[100];
                    var n = serverSocket.Read(buf);
                    if (!buf.Take(n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                    {
                        throw new Exception("client message failed");
                    }

                    // Expect error in here
                    try
                    {
                        serverSocket.Write(Encoding.ASCII.GetBytes("ca va?"));
                    }
                    catch (Exception ex)
                    {
                        if (ex.Message != "disco: a server should not write on one-way patterns")
                        {
                            throw new Exception($"Unexpected Server Exception: {ex.ToString()}");
                        }
                        else
                        {
                            return;
                        }
                    }
                    throw new Exception("Server should not write in one way pattern");
                }
            });

            // Run the client
            var clientSocket = Apis.Connect("tcp", address, port, clientConfig);

            clientSocket.Write(Encoding.ASCII.GetBytes("hello"));                 
        }

        private void RunTwoWayTest(Config clientConfig, Config serverConfig, int port = 1800)
        {
            // set up remote keys
            serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey;
            clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey;

            var address = "127.0.0.1";

            // get a Noise.listener
           
                // run the server and Accept one connection

                Task.Factory.StartNew(() =>
                {
                    using (var listener = Apis.Listen(address, serverConfig, port))
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
            var clientSocket = Apis.Connect("tcp", address, port, clientConfig);

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


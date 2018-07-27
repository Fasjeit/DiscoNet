namespace DiscoNet.Tests
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Text;
    using System.Threading.Tasks;

    using DiscoNet.Net;
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    using Xunit;

    public class ConnectionTest
    {
        private const int IterationCount = 100;

        private static readonly Config.PublicKeyVerifierDeligate Verifier = (x, y) => true;

        [Fact]
        public async Task TestSeveralWriteRoutines()
        {
            var clientConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                StaticPublicKeyProof = new byte[] { },
                PublicKeyVerifier = ConnectionTest.Verifier
            };

            var serverConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                StaticPublicKeyProof = new byte[] { },
                PublicKeyVerifier = ConnectionTest.Verifier
            };

            await this.RunConnectionTest(clientConfig, serverConfig, 1810);
        }

        [Fact]
        public async Task TestHalfDuplex()
        {
            // init
            var clientConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = ConnectionTest.Verifier,
                StaticPublicKeyProof = new byte[] { },
                HalfDuplex = true
            };

            var serverConfig = new Config
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                PublicKeyVerifier = ConnectionTest.Verifier,
                StaticPublicKeyProof = new byte[] { },
                HalfDuplex = true
            };

            await this.RunConnectionTest(clientConfig, serverConfig, 1811);
        }

        private async Task RunConnectionTest(Config clientConfig, Config serverConfig, int port = 1810)
        {
            var address = IPAddress.Loopback;

            var server = Task.Factory.StartNew(
                () =>
                    {
                        using (var listener = Api.Listen(address, serverConfig, port))
                        {
                            var serverSocket = listener.Accept();
                            for (var i = 0; i < ConnectionTest.IterationCount; i++)
                            {
                                var buf = new byte[100];
                                var n = serverSocket.Read(buf, 0, buf.Length);
                                if (!buf.Take(n - 1).SequenceEqual(Encoding.ASCII.GetBytes("hello ")))
                                {
                                    throw new Exception("received message not as expected");
                                }
                            }
                        }
                    });

            // Run the client
            var clientSocket = Api.Connect(address.ToString(), port, clientConfig);

            for (var i = 0; i < ConnectionTest.IterationCount; i++)
            {
                await Task.Factory.StartNew(
                    () =>
                        {
                            var data = Encoding.ASCII.GetBytes("hello " + i % 10);
                            clientSocket.Write(data, 0, data.Length);
                        });
            }

            await server;
            //var ex = await exception;
            //if (ex != null)
            //{
            //    throw ex;
            //}
        }
    }
}
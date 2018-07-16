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

    public class ConnectionTest
    {
        private const int IterationCount = 100;

        private static readonly Config.PublicKeyVerifierDeligate Verifier = (x, y) => true;

        [Fact]
        public async Task TestSeveralWriteRoutines()
        {
            var clientConfig = new Config()
            {
                //#Q_ return random
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                StaticPublicKeyProof = new byte[] { },
                PublicKeyVerifier = Verifier,
            };

            var serverConfig = new Config()
            {
                //#Q_ return random
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                StaticPublicKeyProof = new byte[] { },
                PublicKeyVerifier = Verifier,
            };

            var address = "127.0.0.1";

            var server = Task.Factory.StartNew(() =>
            {
                using (var listener = Apis.Listen(address, serverConfig, 1801))
                {
                    var serverSocket = listener.Accept();
                    for (int i = 0; i < IterationCount; i++)
                    {
                        var buf = new byte[100];
                        var n = serverSocket.Read(buf);
                        if (!buf.Take(n - 1).SequenceEqual(Encoding.ASCII.GetBytes("hello ")))
                        {
                            throw new Exception("received message not as expected");
                        }
                    }
                }
            });

            // Run the client
            var clientSocket = Apis.Connect("tcp", address, 1801, clientConfig);

            for (int i = 0; i < IterationCount; i++)
            {
                await Task.Factory.StartNew(() =>
                {
                    clientSocket.Write(Encoding.ASCII.GetBytes("hello " + i%10));
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

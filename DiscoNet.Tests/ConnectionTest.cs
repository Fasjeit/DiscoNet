//namespace DiscoNet.Tests
//{
//    using System;
//    using System.Linq;
//    using System.Net;
//    using System.Net.Sockets;
//    using System.Text;
//    using System.Threading;
//    using System.Threading.Tasks;

//    using DiscoNet.Net;
//    using DiscoNet.Noise;
//    using DiscoNet.Noise.Enums;

//    using Xunit;

//    public class ConnectionTest
//    {
//        private const int IterationCount = 256;

//        private static readonly Config.PublicKeyVerifierDeligate Verifier = (x, y) => true;

//        [Fact]
//        public async Task TestSeveralWriteRoutines()
//        {
//            var clientConfig = new Config
//            {
//                KeyPair = Asymmetric.GenerateKeyPair(),
//                HandshakePattern = NoiseHandshakeType.NoiseXX,
//                StaticPublicKeyProof = new byte[] { },
//                PublicKeyVerifier = ConnectionTest.Verifier
//            };

//            var serverConfig = new Config
//            {
//                KeyPair = Asymmetric.GenerateKeyPair(),
//                HandshakePattern = NoiseHandshakeType.NoiseXX,
//                StaticPublicKeyProof = new byte[] { },
//                PublicKeyVerifier = ConnectionTest.Verifier
//            };

//            await this.RunConnectionTest(clientConfig, serverConfig, 1810);
//        }

//        [Fact]
//        public async Task TestHalfDuplex()
//        {
//            // init
//            var clientConfig = new Config
//            {
//                KeyPair = Asymmetric.GenerateKeyPair(),
//                HandshakePattern = NoiseHandshakeType.NoiseXX,
//                PublicKeyVerifier = ConnectionTest.Verifier,
//                StaticPublicKeyProof = new byte[] { },
//                HalfDuplex = true
//            };

//            var serverConfig = new Config
//            {
//                KeyPair = Asymmetric.GenerateKeyPair(),
//                HandshakePattern = NoiseHandshakeType.NoiseXX,
//                PublicKeyVerifier = ConnectionTest.Verifier,
//                StaticPublicKeyProof = new byte[] { },
//                HalfDuplex = true
//            };

//            await this.RunConnectionTest(clientConfig, serverConfig, 1811, 10);
//        }

//        private async Task RunConnectionTest(
//            Config clientConfig,
//            Config serverConfig,
//            int port = 1810,
//            int bufSize = 100)
//        {
//            var address = IPAddress.Loopback;

//            var serverBuf = new byte[bufSize];

//            bool serverSeUp = false;
//            var server = Task.Factory.StartNew(
//                () =>
//                {
//                    var listener = new TcpListener(address, port);
//                    listener.Start();
//                    serverSeUp = true;
//                    using (var client = listener.AcceptTcpClient())
//                    {
//                        using (var connection = new Connection(client.GetStream(), serverConfig))
//                        {
//                            for (var i = 0; i < ConnectionTest.IterationCount; i++)
//                            {
//                                var n = connection.Read(serverBuf, 0, serverBuf.Length);

//                                if (n != 6)
//                                {
//                                    throw new Exception("server is supposed to read 6 bytes");
//                                }

//                                if (!serverBuf.Take(n - 1).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
//                                {
//                                    throw new Exception("received message not as expected");
//                                }

//                                // write the message
//                                var written = connection.Write(serverBuf, 0, n);
//                                if (written != 6)
//                                {
//                                    throw new Exception("server is supposed to write 6 bytes");
//                                }
//                            }
//                        }
//                    }

//                    listener.Stop();
//                });

//            while (!serverSeUp)
//            {
//                Thread.Sleep(1000);
//            }

//            // Run the client
//            using (var clientSocket = new TcpClient(address.ToString(), port))
//            {
//                using (var clientConnection = new Connection(clientSocket.GetStream(), clientConfig, true))
//                {
//                    var clientBuf = new byte[bufSize];

//                    for (var i = 0; i < ConnectionTest.IterationCount; i++)
//                    {
//                        await Task.Factory.StartNew(
//                            () =>
//                            {
//                                var data = Encoding.ASCII.GetBytes("hello").Concat(new[] { (byte)i }).ToArray();

//                                var n = clientConnection.Write(data, 0, data.Length);
//                                if (n != 6)
//                                {
//                                    throw new Exception("client is supposed to write 6 bytes");
//                                }

//                                // then read `hello + (i+1)`
//                                var read = clientConnection.Read(clientBuf, 0, clientBuf.Length);

//                                if (read != 6)
//                                {
//                                    throw new Exception("client is supposed to read 6 bytes");
//                                }

//                                if (!clientBuf.Take(read).SequenceEqual(data))
//                                {
//                                    throw new Exception("received message not as expected");
//                                }
//                            });
//                    }

//                    await server;
//                    //var ex = await exception;
//                    //if (ex != null)
//                    //{
//                    //    throw ex;
//                    //}
//                }
//            }
//        }
//    }
//}
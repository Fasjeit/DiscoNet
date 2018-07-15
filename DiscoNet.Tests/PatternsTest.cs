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
            // init
            var clinetConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseKK
            };

            var serverConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseKK
            };

            // set up remote keys
            serverConfig.RemoteKey = clinetConfig.KeyPair.PublicKey;
            clinetConfig.RemoteKey = serverConfig.KeyPair.PrivateKey;

            var address = "127.0.0.1";

            // get a Noise.listener
            var listener = new Listener(address, serverConfig, 1800);

            // run the server and Accept one connection

            Task.Factory.StartNew(() =>
            {
                var serverSocket = listener.Accept();
                var buf = new byte[100];
                var n = serverSocket.Client.Receive(buf);
                if (!buf.Skip(buf.Length - n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
                {
                    throw new System.Exception("client message failed");
                }

                serverSocket.Client.Send(Encoding.ASCII.GetBytes("ca va?"));
            });

            // Run the client
            var clientSocket = DiscoNet.Net.Apis.DialWithDialer("tcp", address, 1800, clinetConfig);

            clientSocket.Write(Encoding.ASCII.GetBytes("hello"));

            var bufClient = new byte[100];
            clientSocket.Read(out bufClient);

            if (!bufClient.SequenceEqual(Encoding.ASCII.GetBytes("ca va?")))
            {
                throw new Exception();
            }
        }
    }
}


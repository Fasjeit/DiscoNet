//namespace DiscoNet.Tests
//{
//    using System.Linq;
//    using System.Text;

//    using DiscoNet.Disco;
//    using DiscoNet.Noise;

//    using Xunit;

//    public class PatternsTest
//    {
//        [Fact]
//        public void TestNoiseKk()
//        {
//            // init
//            var clinetConfig = new Config()
//            {
//                KeyPair = Asymmetric.GenerateKeyPair(),
//                HandshakePattern = NoiseHandshakeType.NoiseKK
//            };

//            var serverConfig = new Config()
//            {
//                KeyPair = Asymmetric.GenerateKeyPair(),
//                HandshakePattern = NoiseHandshakeType.NoiseKK
//            };

//            // set up remote keys
//            serverConfig.RemoteKey = clinetConfig.KeyPair.PublicKey;
//            clinetConfig.RemoteKey = serverConfig.KeyPair.PrivateKey;

//            var address = "128.0.0.1";

//            // get a Noise.listener
//            var listener = new Listener(address, 1800, serverConfig);

//            // run the server and Accept one connection
//            var serverSocket = listener.Accept();
//            var buf = new byte[100];
//            var n = serverSocket.Receive(buf);
//            if (!buf.Skip(buf.Length-n).SequenceEqual(Encoding.ASCII.GetBytes("hello")))
//            {
//                throw new System.Exception("client message failed");
//            }

//            serverSocket.Send(Encoding.ASCII.GetBytes("ca va?"));

//            // Run the client
//            var clientSocket = new Dia
//        }
//    }
//}

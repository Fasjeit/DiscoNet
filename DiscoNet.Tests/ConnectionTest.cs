namespace DiscoNet.Tests
{
    using System;
    using DiscoNet.Disco;
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    public class ConnectionTest
    {
        private static readonly Config.PublicKeyVerifierDeligate Verifier = (x, y) => true;

        public void TestSeveralWriteRoutines()
        {
            var clientConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                StaticPublicKeyProof = new byte[] { },
                PublicKeyVerifier = Verifier,
            };

            var serverConfig = new Config()
            {
                KeyPair = Asymmetric.GenerateKeyPair(),
                HandshakePattern = NoiseHandshakeType.NoiseXX,
                StaticPublicKeyProof = new byte[] { },
                PublicKeyVerifier = Verifier,
            };

            // get a libdisco.listener
            var listener = new Listener("127.0.0.1:0", 1800, serverConfig);

            throw new NotSupportedException();
        }
    }
}

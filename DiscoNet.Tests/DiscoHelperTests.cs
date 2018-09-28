namespace DiscoNet.Tests
{
    using System;
    using System.IO;
    using System.Linq;

    using DiscoNet.Net;

    using Xunit;

    public class DiscoHelperTests
    {
        [Fact]
        public void TestCreationKeys()
        {
            // temporary files
            var discoKeyPairFile = "discoKeyPairFile";
            var rootPrivateKeyFile = "rootPrivateKeyFile";
            var rootPublicKeyFile = "rootPublicKeyFile";
            try
            {
                // Generate Disco Key pair
                var keyPair = DiscoHelper.GenerateAndSaveDiscoKeyPair(discoKeyPairFile);

                // Load Disco Key pair
                var keyPairTemp = DiscoHelper.LoadDiscoKeyPair(discoKeyPairFile);

                // compare
                if (!keyPairTemp.PrivateKey.SequenceEqual(keyPair.PrivateKey)
                    || !keyPairTemp.PublicKey.SequenceEqual(keyPair.PublicKey))
                {
                    throw new Exception("Disco key pair generated and loaded are different");
                }

                // generate root key
                DiscoHelper.GenerateAndSaveDiscoRootKeyPair(rootPrivateKeyFile, rootPublicKeyFile);

                // load private root key
                var rootPriv = DiscoHelper.LoadDiscoRootPrivateKey(rootPrivateKeyFile);

                // load public root key
                var rootPub = DiscoHelper.LoadDiscoRootPublicKey(rootPublicKeyFile);

                // create a proof
                var proof = DiscoHelper.CreateStaticPublicKeyProof(rootPriv, keyPair.PublicKey);

                // verify the proof
                var verifier = DiscoHelper.CreatePublicKeyVerifier(rootPub);
                if (!verifier(keyPair.PublicKey, proof))
                {
                    throw new Exception("cannot verify proof");
                }
            }
            finally
            {
                DiscoHelperTests.CleanUpFile(discoKeyPairFile);
                DiscoHelperTests.CleanUpFile(rootPrivateKeyFile);
                DiscoHelperTests.CleanUpFile(rootPublicKeyFile);
            }
        }

        private static void CleanUpFile(string fileName)
        {
            if (File.Exists(fileName))
            {
                File.Delete(fileName);
            }
        }
    }
}
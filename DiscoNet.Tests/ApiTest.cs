namespace DiscoNet.Tests
{
    using System;
    using System.IO;
    using System.Linq;

    using DiscoNet.Net;

    using Xunit;

    public class ApiTest
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
                var keyPair = Api.GenerateAndSaveDiscoKeyPair(discoKeyPairFile);

                // Load Disco Key pair
                var keyPairTemp = Api.LoadDiscoKeyPair(discoKeyPairFile);

                // compare
                if (!keyPairTemp.PrivateKey.SequenceEqual(keyPair.PrivateKey)
                    || !keyPairTemp.PublicKey.SequenceEqual(keyPair.PublicKey))
                {
                    throw new Exception("Disco key pair generated and loaded are different");
                }

                // generate root key
                Api.GenerateAndSaveDiscoRootKeyPair(rootPrivateKeyFile, rootPublicKeyFile);

                // load private root key
                var rootPriv = Api.LoadDiscoRootPrivateKey(rootPrivateKeyFile);

                // load public root key
                var rootPub = Api.LoadDiscoRootPublicKey(rootPublicKeyFile);

                // create a proof
                var proof = Api.CreateStaticPublicKeyProof(rootPriv, keyPair.PublicKey);

                // verify the proof
                var verifior = Api.CreatePublicKeyVerifier(rootPub);
                if (!verifior(keyPair.PublicKey, proof))
                {
                    throw new Exception("cannot verify proof");
                }
            }
            finally
            {
                ApiTest.CleanUpFile(discoKeyPairFile);
                ApiTest.CleanUpFile(rootPrivateKeyFile);
                ApiTest.CleanUpFile(rootPublicKeyFile);
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
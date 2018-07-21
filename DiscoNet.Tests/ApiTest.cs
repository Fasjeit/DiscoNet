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
                var keyPair = Apis.GenerateAndSaveDiscoKeyPair(discoKeyPairFile);

                // Load Disco Key pair
                var keyPairTemp = Apis.LoadDiscoKeyPair(discoKeyPairFile);

                // compare
                if (!keyPairTemp.PrivateKey.SequenceEqual(keyPair.PrivateKey)
                    || !keyPairTemp.PublicKey.SequenceEqual(keyPair.PublicKey))
                {
                    throw new Exception("Disco key pair generated and loaded are different");
                }

                // generate root key
                Apis.GenerateAndSaveDiscoRootKeyPair(rootPrivateKeyFile, rootPublicKeyFile);

                // load private root key
                var rootPriv = Apis.LoadDiscoRootPrivateKey(rootPrivateKeyFile);

                // load public root key
                var rootPub = Apis.LoadDiscoRootPublicKey(rootPublicKeyFile);

                // create a proof
                var proof = Apis.CreateStaticPublicKeyProof(rootPriv, keyPair.PublicKey);

                // verify the proof
                var verifior = Apis.CreatePublicKeyVerifier(rootPub);
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
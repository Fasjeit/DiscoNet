namespace DiscoNet.Net
{
    using System;
    using System.IO;
    using System.Net.Sockets;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;
    using DiscoNet.Noise.Pattern;

    using Sodium;

    using StrobeNet.Extensions;

    using KeyPair = DiscoNet.KeyPair;

    public static class Apis
    {
        /// <summary>
        /// Disco peer initialization
        /// </summary>
        /// <param name="handshakeType">Noise handshake patern</param>
        /// <param name="initiator">This party initiates connection</param>
        /// <param name="prologue">Prologue string, some data prior to handshake</param>
        /// <param name="s">local static key</param>
        /// <param name="e">lecal ephermeral key</param>
        /// <param name="rs">remote static key</param>
        /// <param name="re">remote ephemeral key</param>
        /// <returns></returns>
        public static HandshakeState InitializeDisco(
            NoiseHandshakeType handshakeType,
            bool initiator,
            byte[] prologue,
            KeyPair s,
            KeyPair e,
            KeyPair rs,
            KeyPair re)
        {
            var handshakePattern = HandshakePattern.GetPattern(handshakeType);

            var handshakeState = new HandshakeState
            {
                SymmetricState = new SymmetricState($"Noise_{handshakePattern.Name}_25519_STROBEv1.0.2"),
                Initiator = initiator,
                ShouldWrite = initiator
            };

            if (prologue != null)
            {
                handshakeState.SymmetricState.MixHash(prologue);
            }

            if (s != null)
            {
                handshakeState.S = s;
            }

            if (e != null)
            {
                throw new NotSupportedException("disco: fallback patterns are not implemented");
            }

            if (rs != null)
            {
                handshakeState.Rs = rs;
            }

            if (re != null)
            {
                throw new NotSupportedException("disco: fallback patterns are not implemented");
            }

            //Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern,
            //with the specified public key as input (see Section 7 for an explanation of pre-messages).
            //If both initiator and responder have pre-messages, the initiator's public keys are hashed first.

            // initiator pre-message pattern
            foreach (var token in handshakePattern.PreMessagePatterns[0])
            {
                if (token == Tokens.TokenS)
                {
                    if (initiator)
                    {
                        if (s == null)
                        {
                            throw new Exception("disco: the static key of the client should be set");
                        }

                        handshakeState.SymmetricState.MixHash(s.PublicKey);
                    }
                    else
                    {
                        if (rs == null)
                        {
                            throw new Exception("disco: the remote static key of the server should be set");
                        }

                        handshakeState.SymmetricState.MixHash(rs.PublicKey);
                    }
                }
                else
                {
                    throw new Exception("disco: token of pre-message not supported");
                }
            }

            // responder pre-message pattern
            foreach (var token in handshakePattern.PreMessagePatterns[1])
            {
                if (token == Tokens.TokenS)
                {
                    if (initiator)
                    {
                        if (rs == null)
                        {
                            throw new Exception("disco: the remote static key of the client should be set");
                        }

                        handshakeState.SymmetricState.MixHash(rs.PublicKey);
                    }
                    else
                    {
                        if (s == null)
                        {
                            throw new Exception("disco: the static key of the server should be set");
                        }

                        handshakeState.SymmetricState.MixHash(s.PublicKey);
                    }
                }
                else
                {
                    throw new NotSupportedException("disco: token of pre - message not supported");
                }
            }

            handshakeState.MessagePatterns = handshakePattern.MessagePatterns;
            return handshakeState;
        }

        /// <summary>
        /// Establish connection to Disco server and perform handshake
        /// </summary>
        /// <param name="address">Server ip address</param>
        /// <param name="port">server tcp port</param>
        /// <param name="config">Noise configuration</param>
        /// <returns></returns>
        public static Connection Connect(string address, int port, Config config)
        {
            if (config == null)
            {
                throw new NullReferenceException(nameof(config));
            }

            Apis.CheckRequirments(false, config);

            var tcpClient = new TcpClient(address, port);

            var connection = Apis.Client(tcpClient, config);

            // Do the handshake
            connection.HandShake();

            return connection;
        }

        /// <summary>
        /// Listen for Disco client connections
        /// </summary>
        /// <param name="address">ip address for listening</param>
        /// <param name="config">Noise configuration</param>
        /// <param name="port">tcp port for listening</param>
        /// <returns></returns>
        public static Listener Listen(string address, Config config, int port = 1800)
        {
            var listener = new Listener(address, config, port);
            listener.Start();
            return listener;
        }

        /// <summary>
        /// Create static proof for disco peer
        /// </summary>
        /// <remarks>
        /// StaticPublicKeyProof sometimes required
        /// for peers that are sending their static public key at some
        /// point during the handshake
        /// </remarks>
        /// <param name="sodiumPrivateKey"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static byte[] CreateStaticPublicKeyProof(byte[] sodiumPrivateKey, byte[] publicKey)
        {
            if (publicKey.Length != 32)
            {
                throw new Exception("disco: length of public key passed is incorrect (should be 32)");
            }

            return PublicKeyAuth.SignDetached(publicKey, sodiumPrivateKey);
        }

        /// <summary>
        /// Create callback function for public key verification
        /// </summary>
        /// <remarks>
        /// PublicKeyVerifier sometimes required
        /// for peers that are receiving a static public key at some
        /// point during the handshake
        /// </remarks>
        /// <param name="rootPublicKey"></param>
        /// <returns></returns>
        public static Config.PublicKeyVerifierDeligate CreatePublicKeyVerifier(byte[] rootPublicKey)
        {
            return (publicKey, proof) =>
                {
                    if (publicKey.Length != 32)
                    {
                        return false;
                    }

                    return PublicKeyAuth.VerifyDetached(proof, publicKey, rootPublicKey);
                };
        }

        /// <summary>
        /// Generate a disco key pair (X25519 key pair)
        /// and save it to a file in hexadecimal form.
        /// </summary>
        /// <param name="fileName">Filepath to save key</param>
        /// <returns></returns>
        public static KeyPair GenerateAndSaveDiscoKeyPair(string fileName)
        {
            var keyPair = Asymmetric.GenerateKeyPair();

            File.WriteAllText(fileName, keyPair.ExportPublicKey() + keyPair.ExportPrivateKey());

            return keyPair;
        }

        /// <summary>
        /// Load Dico keypair from file
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        public static KeyPair LoadDiscoKeyPair(string fileName)
        {
            var hex = File.ReadAllText(fileName);
            if (hex.Length != 128)
            {
                throw new Exception("Disco: Disco key pair file is not correctly formated");
            }

            var keyPair = new KeyPair();
            keyPair.ImportPublicKey(hex.Substring(0, 64));
            keyPair.ImportPrivateKey(hex.Substring(64, 64));

            return keyPair;
        }

        /// <summary>
        /// Generate an ed25519 root key pair and save the private and public parts in different files.
        /// </summary>
        /// <param name="discoRootPrivateKeyFile">Path to private key file</param>
        /// <param name="discoRootPublicKeyFile">Path to public key file</param>
        public static void GenerateAndSaveDiscoRootKeyPair(
            string discoRootPrivateKeyFile,
            string discoRootPublicKeyFile)
        {
            var keyPair = PublicKeyAuth.GenerateKeyPair();

            File.WriteAllText(discoRootPrivateKeyFile, keyPair.PrivateKey.ToHexString());
            File.WriteAllText(discoRootPublicKeyFile, keyPair.PublicKey.ToHexString());
        }

        /// <summary>
        /// Load public root key from file
        /// </summary>
        /// <param name="discoRootPublicKeyFile">Path to public key file</param>
        /// <returns></returns>
        public static byte[] LoadDiscoRootPublicKey(string discoRootPublicKeyFile)
        {
            var hex = File.ReadAllText(discoRootPublicKeyFile);
            if (hex.Length != 64)
            {
                throw new Exception("Disco: Disco root public key file is not correctly formated");
            }

            return hex.ToByteArray();
        }

        /// <summary>
        /// Load private root key from file
        /// </summary>
        /// <param name="discoRootPrivaeKeyFile">Path to private key file</param>
        /// <returns></returns>
        public static byte[] LoadDiscoRootPrivateKey(string discoRootPrivaeKeyFile)
        {
            var hex = File.ReadAllText(discoRootPrivaeKeyFile);
            if (hex.Length != 128)
            {
                throw new Exception("Disco: Disco root private key file is not correctly formated");
            }

            return hex.ToByteArray();
        }

        /// <summary>
        /// Get new Disco server side connection
        /// </summary>
        /// <param name="connection">Tcp client for establishing connecion</param>
        /// <param name="config">Noise configuration</param>
        /// <returns></returns>
        internal static Connection Server(TcpClient connection, Config config)
        {
            return new Connection(connection, config);
        }

        /// <summary>
        /// Get new Disco client side connection
        /// </summary>
        /// <param name="connection">Tcp client for establishing connecion</param>
        /// <param name="config">Noise configuration</param>
        /// <returns></returns>
        internal static Connection Client(TcpClient connection, Config config)
        {
            return new Connection(connection, config, true);
        }

        /// <summary>
        /// Check Noise configuration requirmens
        /// </summary>
        /// <param name="isClient"></param>
        /// <param name="config"></param>
        internal static void CheckRequirments(bool isClient, Config config)
        {
            var ht = config.HandshakePattern;
            if (ht == NoiseHandshakeType.NoiseNX || ht == NoiseHandshakeType.NoiseKX || ht == NoiseHandshakeType.NoiseXX
                || ht == NoiseHandshakeType.NoiseIX)
            {
                if (isClient && config.PublicKeyVerifier == null)
                {
                    throw new Exception("Disco: no public key verifier set in Config");
                }

                if (!isClient && config.StaticPublicKeyProof == null)
                {
                    throw new Exception("Disco: no public key proof set in Config");
                }
            }

            if (ht == NoiseHandshakeType.NoiseXN || ht == NoiseHandshakeType.NoiseXK || ht == NoiseHandshakeType.NoiseXX
                || ht == NoiseHandshakeType.NoiseX || ht == NoiseHandshakeType.NoiseIN
                || ht == NoiseHandshakeType.NoiseIK || ht == NoiseHandshakeType.NoiseIX)
            {
                if (isClient && config.StaticPublicKeyProof == null)
                {
                    throw new Exception("Disco: no public key proof set in Config");
                }

                if (!isClient && config.PublicKeyVerifier == null)
                {
                    throw new Exception("Disco: no public key verifier set in Config");
                }
            }

            if (ht == NoiseHandshakeType.NoiseNNpsk2 && config.PreSharedKey.Length != 32)
            {
                throw new Exception("noise: a 32-byte pre-shared key needs to be passed as noise.Config");
            }
        }
    }
}
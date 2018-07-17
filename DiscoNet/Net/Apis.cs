namespace DiscoNet.Net
{
    using System;
    using System.Net;
    using System.Net.Sockets;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;
    using DiscoNet.Disco;
    using System.IO;
    using System.Linq;
    using StrobeNet.Extensions;
    using DiscoNet.Noise.Pattern;

    public static class Apis
    {
        //#Q_
        const int MaxConnecions = 1;

        // This allows you to initialize a peer.
        // * see `patterns` for a list of available handshakePatterns
        // * initiator = false means the instance is for a responder
        // * prologue is a byte string record of anything that happened prior the Noise handshakeState
        // * s, e, rs, re are the local and remote static/ephemeral key pairs to be set (if they exist)
        // the function returns a handshakeState object.
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
                ShouldWrite = initiator,
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
        /// Server returns a new Disco server side connection
        /// using net.Conn as the underlying transport.
        /// The configuration config must be non-nil and must include
        /// at least one certificate or else set GetCertificate.
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="config"></param>
        /// <returns></returns>
        internal static Connection Server(TcpClient connection, Config config)
        {
            return new Connection() { SocketConnection = connection, config = config, };
        }

        /// <summary>
        ///  Client returns a new Disco client side connection
        /// using conn as the underlying transport.
        /// The config cannot be nil: users must set either ServerName or
        /// InsecureSkipVerify in the config.
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="config"></param>
        /// <returns></returns>
        internal static Connection Client(TcpClient connection, Config config)
        {
            return new Connection() { SocketConnection = connection, config = config, IsClient = true };
        }

        public static Connection Connect(string network, string addr, int port, Config config)
        {
            if (config == null)
            {
                throw new NullReferenceException(nameof(config));
            }

            CheckRequirments(false, config);

            //var ipAddress = IPAddress.Parse(addr);
            //IPEndPoint localEndPoint = new IPEndPoint(ipAddress, port);

            //var rawConn = new TcpListener(ipAddress, port);
            //rawConn.Start();

            var tcpClient = new TcpClient(addr, port);

            var connection = Client(tcpClient, config);

            // Do the handshake
            connection.HandShake();

            return connection;
        }

        internal static void CheckRequirments(bool isClient, Config config)
        {
            var ht = config.HandshakePattern;
            if (ht == NoiseHandshakeType.NoiseNX ||
                ht == NoiseHandshakeType.NoiseKX ||
                ht == NoiseHandshakeType.NoiseXX ||
                ht == NoiseHandshakeType.NoiseIX)
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

            if (ht == NoiseHandshakeType.NoiseXN ||
                ht == NoiseHandshakeType.NoiseXK ||
                ht == NoiseHandshakeType.NoiseXX ||
                ht == NoiseHandshakeType.NoiseX ||
                ht == NoiseHandshakeType.NoiseIN ||
                ht == NoiseHandshakeType.NoiseIK ||
                ht == NoiseHandshakeType.NoiseIX)
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

        public static Listener Listen(string address, Config config, int port = 1800)
        {
            var listener = new Listener(address, config, port);
            listener.Start();
            return listener;
        }

        // CreateStaticPublicKeyProof can be used to create the proof
        // StaticPublicKeyProof sometimes required in a libdisco.Config
        // for peers that are sending their static public key at some
        // point during the handshake
        public static byte[] CreateStaticPublicKeyProof(byte[] sodiumPrivateKey, byte[] publicKey)
        {
            if (publicKey.Length != 32)
            {
                throw new Exception("disco: length of public key passed is incorrect (should be 32)");
            }
            return Sodium.PublicKeyAuth.SignDetached(publicKey, sodiumPrivateKey);
        }

        // CreatePublicKeyVerifier can be used to create the callback
        // function PublicKeyVerifier sometimes required in a libdisco.Config
        // for peers that are receiving a static public key at some
        // point during the handshake
        public static Config.PublicKeyVerifierDeligate CreatePublicKeyVerifier(byte[] rootPublicKey)
        {
            return (publicKey, proof) =>
            {
                if (publicKey.Length != 32)
                {
                    return false;
                }
                return Sodium.PublicKeyAuth.VerifyDetached(proof, publicKey, rootPublicKey);
            };
        }

        // GenerateAndSaveDiscoKeyPair generates a disco key pair (X25519 key pair)
        // and saves it to a file in hexadecimal form. You can use ExportPublicKey() to
        // export the public key part.
        public static KeyPair GenerateAndSaveDiscoKeyPair(string fileName)
        {
            var keyPair = Asymmetric.GenerateKeyPair();

            File.WriteAllText(fileName, keyPair.ExportPublicKey() + keyPair.ExportPrivateKey());

            return keyPair;
        }

        // LoadDiscoKeyPair reads and parses a public/private key pair from a pair
        // of files.
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

        // GenerateAndSaveDiscoRootKeyPair generates an ed25519 root key pair and save the private and public parts in different files.
        public static void GenerateAndSaveDiscoRootKeyPair(string discoRootPrivateKeyFile, string discoRootPublicKeyFile)
        {
            var keyPair = Sodium.PublicKeyAuth.GenerateKeyPair();

            File.WriteAllText(discoRootPrivateKeyFile, keyPair.PrivateKey.ToHexString());
            File.WriteAllText(discoRootPublicKeyFile, keyPair.PublicKey.ToHexString());
        }

        // LoadDiscoRootPublicKey reads and parses a public Root key from a
        // file. The file contains an 32-byte ed25519 public key in hexadecimal
        public static byte[] LoadDiscoRootPublicKey(string discoRootPublicKeyFile)
        {
            var hex = File.ReadAllText(discoRootPublicKeyFile);
            if (hex.Length != 64)
            {
                throw new Exception("Disco: Disco root public key file is not correctly formated");
            }
            return hex.ToByteArray();
        }

        // LoadDiscoRootPrivateKey reads and parses a private Root key from a
        // file. The file contains an 32-byte ed25519 private key in hexadecimal
        public static byte[] LoadDiscoRootPrivateKey(string discoRootPrivaeKeyFile)
        {
            var hex = File.ReadAllText(discoRootPrivaeKeyFile);
            if (hex.Length != 128)
            {
                throw new Exception("Disco: Disco root private key file is not correctly formated");
            }
            return hex.ToByteArray();
        }
    }
}
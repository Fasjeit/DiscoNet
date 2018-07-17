﻿namespace DiscoNet.Net
{
    using System;
    using System.Net;
    using System.Net.Sockets;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;
    using DiscoNet.Disco;

    public static class Apis
    {
        //#Q_
        const int MaxConnecions = 1;

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
        public static byte[] CreateStaticPublicKeyProof(Sodium.KeyPair keyPair, byte[] publicKey)
        {
            if (publicKey.Length != 32)
            {
                throw new Exception("disco: length of public key passed is incorrect (should be 32)");
            }
            return Sodium.PublicKeyAuth.SignDetached(publicKey, keyPair.PrivateKey);
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
    }
}
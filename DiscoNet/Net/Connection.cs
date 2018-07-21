namespace DiscoNet.Net
{
    using System;
    using System.Linq;
    using System.Net.Sockets;
    using System.Threading;

    using DiscoNet.Noise.Enums;

    using StrobeNet;

    /// <summary>
    /// Represents a secured connection
    /// </summary>
    public class Connection
    {
        private readonly Config config;

        private readonly Mutex halfDuplexLock = new Mutex();

        private readonly Mutex handshakeMutex = new Mutex();

        private readonly Mutex inLock = new Mutex();

        private readonly bool isClient;

        private readonly Mutex outLock = new Mutex();

        private readonly TcpClient tcpConnection;

        private bool handshakeComplite;

        private byte[] inputBuffer = { };

        // half duplex
        private bool isHalfDuplex;

        // IsRemoteAuthenticated can be used to check if the remote peer 
        // has been properly authenticated.It serves no real purpose for 
        // the moment as the handshake will not go through if a peer is not 
        // properly authenticated in patterns where the peer needs to be authenticated.
        private bool isRemoteAuthenticated;

        // input/output
        private Strobe strobeIn;

        private Strobe strobeOut;

        /// <summary>
        /// Create Disco connection
        /// </summary>
        /// <param name="tcpConnection">Tcp connection to use</param>
        /// <param name="config">Noise config</param>
        /// <param name="isClient"></param>
        public Connection(TcpClient tcpConnection, Config config, bool isClient = false)
        {
            this.tcpConnection = tcpConnection;
            this.config = config;
            this.isClient = isClient;
        }

        /// <summary>
        /// Write data to connection
        /// </summary>
        /// <param name="data">Data to write</param>
        /// <param name="exeption">Ouput exeption</param>
        /// <returns></returns>
        public int Write(byte[] data, out Exception exeption)
        {
            // If this is a one-way pattern, do some checks
            var handshakePattern = this.config.HandshakePattern;
            if (!this.isClient && (handshakePattern == NoiseHandshakeType.NoiseN
                                   || handshakePattern == NoiseHandshakeType.NoiseK
                                   || handshakePattern == NoiseHandshakeType.NoiseX))
            {
                throw new Exception("disco: a server should not write on one-way patterns");
            }

            // Make sure to go through the handshake first
            try
            {
                this.HandShake();
            }
            catch (Exception ex)
            {
                exeption = ex;
                return 0;
            }

            Mutex mutex;

            // Lock the write socket
            if (this.isHalfDuplex)
            {
                mutex = this.halfDuplexLock;
            }
            else
            {
                mutex = this.outLock;
            }

            mutex.WaitOne();
            try
            {
                var totalBytes = 0;

                // process the data in a loop
                while (data.Length > 0)
                {
                    try
                    {
                        var dataLen = data.Length > Config.NoiseMaxPlaintextSize
                                          ? Config.NoiseMaxPlaintextSize
                                          : data.Length;

                        // Encrypt
                        var ciphertext = this.strobeOut.SendEncUnauthenticated(false, data.Take(dataLen).ToArray());
                        ciphertext = ciphertext.Concat(this.strobeOut.SendMac(false, 16)).ToArray();

                        // header (length)
                        var length = new[] { (byte)(ciphertext.Length >> 8), (byte)(ciphertext.Length % 256) };

                        // Send data
                        this.tcpConnection.Client.Send(length.Concat(ciphertext).ToArray());

                        // prepare next loop iteration
                        totalBytes += dataLen;
                        data = data.Skip(dataLen).ToArray();
                    }
                    catch (Exception ex)
                    {
                        exeption = ex;
                        return totalBytes;
                    }
                }

                exeption = null;
                return totalBytes;
            }
            finally
            {
                mutex.ReleaseMutex();
            }
        }

        /// <summary>
        /// Read data from connection
        /// </summary>
        /// <param name="data">Return buffer</param>
        /// <param name="exeption">output exeption</param>
        /// <returns></returns>
        public int Read(byte[] data, out Exception exeption)
        {
            if (data == null || data.Length == 0)
            {
                exeption = null;
                return 0;
            }

            // Make sure to go through the handshake first
            try
            {
                this.HandShake();
            }
            catch (Exception ex)
            {
                exeption = ex;
                return 0;
            }

            // If this is a one-way pattern, do some checks
            var handshakePattern = this.config.HandshakePattern;
            if (this.isClient && (handshakePattern == NoiseHandshakeType.NoiseN
                                  || handshakePattern == NoiseHandshakeType.NoiseK
                                  || handshakePattern == NoiseHandshakeType.NoiseX))
            {
                throw new Exception("disco: a client should not read on one - way patterns");
            }

            // Lock the read socket
            Mutex mutex;
            if (this.isHalfDuplex)
            {
                mutex = this.halfDuplexLock;
            }
            else
            {
                mutex = this.inLock;
            }

            mutex.WaitOne();
            try
            {
                // read whatever there is to read in the buffer
                var readSoFar = 0;
                if (this.inputBuffer.Length > 0)
                {
                    var toRead = this.inputBuffer.Length > data.Length ? data.Length : this.inputBuffer.Length;
                    this.inputBuffer.CopyTo(data, readSoFar);
                    if (this.inputBuffer.Length > data.Length)
                    {
                        this.inputBuffer = this.inputBuffer.Skip(data.Length).ToArray();

                        exeption = null;
                        return data.Length;
                    }

                    readSoFar += toRead;
                    this.inputBuffer = new byte[] { };
                }

                // read header from socket
                byte[] bufHeader;
                try
                {
                    bufHeader = this.ReadFromUntil(this.tcpConnection, 2);
                }
                catch (Exception ex)
                {
                    exeption = ex;
                    return 0;
                }

                var length = (bufHeader[0] << 8) | bufHeader[1];

                if (length > Config.NoiseMessageLength)
                {
                    exeption = new Exception("disco: Disco message received exceeds DiscoMessageLength");
                    return 2;
                }

                byte[] noiseMessage;
                // read noise message from socket
                try
                {
                    noiseMessage = this.ReadFromUntil(this.tcpConnection, length);
                }
                catch (Exception ex)
                {
                    exeption = ex;
                    return 2;
                }
                // decrypt
                if (length < 16)
                {
                    exeption = new Exception("disco: the received payload is shorter 16 bytes");
                    return 2 + length;
                }

                var plaintextLength = noiseMessage.Length - 16;
                var plaintext = this.strobeIn.RecvEncUnauthenticated(
                    false,
                    noiseMessage.Take(plaintextLength).ToArray());
                var ok = this.strobeIn.RecvMac(false, noiseMessage.Skip(plaintextLength).ToArray());

                if (!ok)
                {
                    exeption = new Exception("disco: cannot decrypt the payload");
                    return 2 + length;
                }

                // append to the input buffer
                this.inputBuffer = this.inputBuffer.Concat(plaintext).ToArray();

                // read whatever we can read
                var rest = data.Length - readSoFar;
                var restToRead = this.inputBuffer.Length > rest ? rest : this.inputBuffer.Length;
                this.inputBuffer.CopyTo(data, readSoFar);
                if (this.inputBuffer.Length > restToRead)
                {
                    this.inputBuffer = this.inputBuffer.Skip(readSoFar).ToArray();

                    exeption = null;
                    return data.Length;
                }

                // we haven't filled the buffer
                readSoFar += restToRead;
                this.inputBuffer = new byte[] { };

                exeption = null;
                return readSoFar;
            }

            finally
            {
                mutex.ReleaseMutex();
            }
        }

        /// <summary>
        /// Read delected amount of bytes from connection
        /// </summary>
        /// <param name="connection">Connection to read from</param>
        /// <param name="n">Number of bytes</param>
        /// <returns></returns>
        private byte[] ReadFromUntil(TcpClient connection, int n)
        {
            var result = new byte[n];
            connection.Client.Receive(result, 0, n, SocketFlags.Partial);
            return result;
        }

        /// <summary>
        /// Perform handshake protocol if it has not been already run.
        /// </summary>
        /// <remarks>
        /// Most uses of this package need not call Handshake explicitly:
        /// the first Read or Write will call it automatically.
        /// </remarks>
        internal void HandShake()
        {
            // Locking the handshakeMutex
            this.handshakeMutex.WaitOne();
            try
            {
                Strobe c1;
                Strobe c2;
                byte[] receivedPayload = null;

                // did we already go through the handshake?
                if (this.handshakeComplite)
                {
                    return;
                }

                KeyPair remoteKeyPair = null;
                if (this.config.RemoteKey != null)
                {
                    if (this.config.RemoteKey.Length != 32)
                    {
                        throw new Exception("disco: the provided remote key is not 32-byte");
                    }

                    remoteKeyPair = new KeyPair() { PublicKey = new byte[this.config.RemoteKey.Length] };
                    Array.Copy(this.config.RemoteKey, remoteKeyPair.PublicKey, this.config.RemoteKey.Length);
                }

                var handshakeState = Api.InitializeDisco(
                    this.config.HandshakePattern,
                    this.isClient,
                    this.config.Prologue,
                    this.config.KeyPair,
                    null,
                    remoteKeyPair,
                    null);

                // pre-shared key
                handshakeState.Psk = this.config.PreSharedKey;

                do
                {
                    // start handshake
                    if (handshakeState.ShouldWrite)
                    {
                        // we're writing the next message pattern
                        // if it's the message pattern and we're sending a static key, we also send a proof
                        // TODO: is this the best way of sending a proof :/ ?
                        byte[] bufToWrite;

                        if (handshakeState.MessagePatterns.Length <= 2 && this.config.StaticPublicKeyProof != null)
                        {
                            (c1, c2) = handshakeState.WriteMessage(this.config.StaticPublicKeyProof, out bufToWrite);
                        }
                        else
                        {
                            (c1, c2) = handshakeState.WriteMessage(new byte[] { }, out bufToWrite);
                        }

                        // header (length)
                        var length = new[] { (byte)(bufToWrite.Length >> 8), (byte)(bufToWrite.Length % 256) };
                        // write
                        var dataToWrite = length.Concat(bufToWrite).ToArray();
                        this.tcpConnection.Client.Send(dataToWrite);
                    }
                    else
                    {
                        var bufHeader = this.ReadFromUntil(this.tcpConnection, 2);

                        var length = (bufHeader[0] << 8) | bufHeader[1];

                        if (length > Config.NoiseMessageLength)
                        {
                            throw new Exception("disco: Disco message received exceeds DiscoMessageLength");
                        }

                        var noiseMessage = this.ReadFromUntil(this.tcpConnection, length);

                        (c1, c2) = handshakeState.ReadMessage(noiseMessage, out receivedPayload);
                    }
                }
                while (c1 == null);

                // Has the other peer been authenticated so far?
                if (!this.isRemoteAuthenticated && this.config.PublicKeyVerifier != null)
                {
                    byte isRemoteStaticKeySet = 0;
                    // test if remote static key is empty
                    foreach (var val in handshakeState.Rs.PublicKey)
                    {
                        isRemoteStaticKeySet |= val;
                    }

                    if (isRemoteStaticKeySet != 0)
                    {
                        // a remote static key has been received. Verify it
                        if (!this.config.PublicKeyVerifier(handshakeState.Rs.PublicKey, receivedPayload))
                        {
                            throw new Exception("disco: the received public key could not be authenticated");
                        }
                    }
                }

                // Processing the final handshake message returns two CipherState objects
                // the first for encrypting transport messages from initiator to responder
                // and the second for messages in the other direction.
                if (c2 != null)
                {
                    if (this.isClient)
                    {
                        (this.strobeOut, this.strobeIn) = (c1, c2);
                    }
                    else
                    {
                        (this.strobeOut, this.strobeIn) = (c2, c1);
                    }
                }
                else
                {
                    this.isHalfDuplex = true;
                    this.strobeIn = c1;
                    this.strobeOut = c1;
                }

                // TODO: preserve c.hs.symmetricState.h
                // At that point the HandshakeState should be deleted except for the hash value h, which may be used for post-handshake channel binding (see Section 11.2).
                handshakeState.Dispose();

                // no errors :)
                this.handshakeComplite = true;
            }
            finally
            {
                this.handshakeMutex.ReleaseMutex();
            }
        }
    }
}
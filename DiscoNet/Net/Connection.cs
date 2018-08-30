namespace DiscoNet.Net
{
    using System;
    using System.Linq;
    using System.Net.Sockets;
    using System.Threading;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    using StrobeNet;

    /// <summary>
    /// Represents a secured connection
    /// </summary>
    public class Connection : IDisposable
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
        /// <param name="offset">Offset of data to read from</param>
        /// <param name="count">Number of bytes to write</param>
        /// <returns>Number of written bytes</returns>
        public int Write(byte[] data, int offset, int count)
        {
            Connection.ValidateParameters(data, offset, count);

            // If this is a one-way pattern, do some checks
            var handshakePattern = this.config.HandshakePattern;
            if (!this.isClient && (handshakePattern == NoiseHandshakeType.NoiseN
                                   || handshakePattern == NoiseHandshakeType.NoiseK
                                   || handshakePattern == NoiseHandshakeType.NoiseX))
            {
                throw new Exception("disco: a server should not write on one-way patterns");
            }

            // Make sure to go through the handshake first
            this.HandShake();

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
                while (count - totalBytes > 0)
                {
                    var dataLen = count > Config.NoiseMaxPlaintextSize ? Config.NoiseMaxPlaintextSize : count;

                    // Encrypt
                    var ciphertext = this.strobeOut.SendEncUnauthenticated(
                        false,
                        data.Skip(offset).Take(dataLen).ToArray());
                    ciphertext = ciphertext.Concat(this.strobeOut.SendMac(false, Symmetric.TagSize)).ToArray();

                    // header (length)
                    var length = new[] { (byte)(ciphertext.Length >> 8), (byte)(ciphertext.Length % 256) };

                    // Send data
                    this.tcpConnection.Client.Send(length.Concat(ciphertext).ToArray());

                    // prepare next loop iteration
                    totalBytes += dataLen;
                    offset += dataLen;
                }

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
        /// <param name="offset">Offset of data to write to</param>
        /// <param name="count">Number of bytes to read</param>
        /// <returns>Number of read bytes</returns>
        public int Read(byte[] data, int offset, int count)
        {
            if (data == null || data.Length == 0)
            {
                return 0;
            }

            Connection.ValidateParameters(data, offset, count);

            // Make sure to go through the handshake first
            this.HandShake();

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
                    var toRead = this.inputBuffer.Length > count ? count : this.inputBuffer.Length;
                    this.inputBuffer.CopyTo(data, readSoFar + offset);
                    if (this.inputBuffer.Length > count)
                    {
                        this.inputBuffer = this.inputBuffer.Skip(count).ToArray();

                        return count;
                    }

                    readSoFar += toRead;
                    this.inputBuffer = new byte[] { };
                }

                // read header from socket
                var bufHeader = this.ReadFromUntil(this.tcpConnection, 2);

                var length = (bufHeader[0] << 8) | bufHeader[1];

                if (length > Config.NoiseMessageLength)
                {
                    throw new Exception("disco: Disco message received exceeds DiscoMessageLength");
                }

                // read noise message from socket
                var noiseMessage = this.ReadFromUntil(this.tcpConnection, length);

                // decrypt
                if (length < Symmetric.TagSize)
                {
                    throw new Exception($"disco: the received payload is shorter {Symmetric.TagSize} bytes");
                }

                var plaintextLength = noiseMessage.Length - Symmetric.TagSize;
                var plaintext = this.strobeIn.RecvEncUnauthenticated(
                    false,
                    noiseMessage.Take(plaintextLength).ToArray());
                var ok = this.strobeIn.RecvMac(false, noiseMessage.Skip(plaintextLength).ToArray());

                if (!ok)
                {
                    throw new Exception("disco: cannot decrypt the payload");
                }

                // append to the input buffer
                this.inputBuffer = this.inputBuffer.Concat(plaintext).ToArray();

                // read whatever we can read
                var rest = count - readSoFar;
                var restToRead = this.inputBuffer.Length > rest ? rest : this.inputBuffer.Length;
                this.inputBuffer.CopyTo(data, readSoFar + offset);
                if (this.inputBuffer.Length > restToRead)
                {
                    this.inputBuffer = this.inputBuffer.Skip(readSoFar).ToArray();

                    return count;
                }

                // we haven't filled the buffer
                readSoFar += restToRead;
                this.inputBuffer = new byte[] { };

                return readSoFar;
            }

            finally
            {
                mutex.ReleaseMutex();
            }
        }

        /// <summary>
        /// Validates user parameters for all Read/Write methods
        /// </summary>
        /// <param name="buffer">Buffer to operate</param>
        /// <param name="offset">Buffer offset</param>
        /// <param name="count">Number of bytes to read/write</param>
        private static void ValidateParameters(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }

            if (count > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(count),
                    $"Not enough bytes in buffer to process, expecting at least {count + offset}");
            }
        }

        /// <summary>
        /// Read detected amount of bytes from connection
        /// </summary>
        /// <param name="connection">Connection to read from</param>
        /// <param name="n">Number of bytes</param>
        /// <returns>Read bytes</returns>
        private byte[] ReadFromUntil(TcpClient connection, int n)
        {
            var result = new byte[n];
            connection.Client.Receive(result, 0, n, SocketFlags.None);
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

            HandshakeState handshakeState = null;
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
                    if (this.config.RemoteKey.Length != Asymmetric.DhLen)
                    {
                        throw new Exception($"disco: the provided remote key is not {Asymmetric.DhLen}-byte");
                    }

                    remoteKeyPair = new KeyPair { PublicKey = new byte[this.config.RemoteKey.Length] };
                    Array.Copy(this.config.RemoteKey, remoteKeyPair.PublicKey, this.config.RemoteKey.Length);
                }

                handshakeState = Api.InitializeDisco(
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
                handshakeState?.Dispose();
                this.handshakeMutex.ReleaseMutex();
            }
        }

        /// <summary>
        /// Dispose connection
        /// </summary>
        public void Dispose()
        {
            this.halfDuplexLock?.Dispose();
            this.handshakeMutex?.Dispose();
            this.inLock?.Dispose();
            this.outLock?.Dispose();
            this.tcpConnection?.Close();
            this.tcpConnection?.Dispose();
        }
    }
}

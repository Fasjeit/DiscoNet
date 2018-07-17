namespace DiscoNet
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;
    using StrobeNet;

    /// <summary>
    /// Represents a secured connection
    /// </summary>
    public class Connection
    {
        public TcpClient SocketConnection
        {
            get;set;
        }

        public bool IsClient { get; set; }

        //HandshakeState
        public Config config { get; set; }
        private HandshakeState HandshakeState { get; set; }

        private bool handshakeComplite { get; set; }

        private Mutex handshakeMutex { get; set; } = new Mutex();

        private Mutex inLock { get; set; } = new Mutex();

        private Mutex outLock { get; set; } = new Mutex(); 

        // Authentication thingies
        private bool isRemoteAuthenticated { get; set; }

        // input/output
        private Strobe strobeIn { get; set; }

        private Strobe strobeOut { get; set; }

        private Byte[] inputBuffer { get; set; } = new byte[] { };

        // half duplex
        private bool isHalfDuplex { get; set; }

        private Mutex halfDuplexLock { get; set; } = new Mutex();

        // Write writes data to the connection.
        public int Write(byte[] data)
        {
            // If this is a one-way pattern, do some checks
            var handshakePattern = this.config.HandshakePattern;
            if (!this.IsClient && (handshakePattern == NoiseHandshakeType.NoiseN || handshakePattern == NoiseHandshakeType.NoiseK || handshakePattern == NoiseHandshakeType.NoiseX))
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
                while (data.Length > 0)
                {
                    var dataLen = data.Length > Config.NoiseMaxPlaintextSize ? Config.NoiseMaxPlaintextSize : data.Length;

                    // Encrypt
                    var ciphertext = this.strobeOut.SendEncUnauthenticated(false, data.Take(dataLen).ToArray());
                    ciphertext = ciphertext.Concat(this.strobeOut.SendMac(false, 16)).ToArray();

                    // header (length)
                    var length = new byte[] { (byte)(ciphertext.Length >> 8), (byte)(ciphertext.Length % 256) };

                    // Send data
                    this.SocketConnection.Client.Send(length.Concat(ciphertext).ToArray());

                    // prepare next loop iteration
                    totalBytes += dataLen;
                    data = data.Skip(dataLen).ToArray();
                }

                return totalBytes;
            }
            finally
            {
                mutex.ReleaseMutex();
            }
        }

        public int Read(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return 0;
            }

            // Make sure to go through the handshake first
            this.HandShake();

            // If this is a one-way pattern, do some checks
            var handshakePattern = this.config.HandshakePattern;
            if (this.IsClient && (handshakePattern == NoiseHandshakeType.NoiseN || handshakePattern == NoiseHandshakeType.NoiseK || handshakePattern == NoiseHandshakeType.NoiseX))
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
                    var toRead = this.inputBuffer.Length > data.Length ? data.Length : (int)this.inputBuffer.Length ;
                    this.inputBuffer.CopyTo(data, readSoFar);
                    if (this.inputBuffer.Length > data.Length)
                    {
                        this.inputBuffer = this.inputBuffer.Skip(data.Length).ToArray();
                        return data.Length;
                    }
                    readSoFar += toRead;
                    this.inputBuffer = new byte[] { };
                }
                // read header from socket
                var bufHeader = this.ReadFromUntil(this.SocketConnection, 2);
                var length = ((int)(bufHeader[0]) << 8) | (int)(bufHeader[1]);

                if (length > Config.NoiseMessageLength)
                {
                    throw new Exception("disco: Disco message received exceeds DiscoMessageLength");
                }

                // read noise message from socket
                var noiseMessage = this.ReadFromUntil(this.SocketConnection, length);

                // decrypt
                if (length < 16)
                {
                    throw new Exception("disco: the received payload is shorter 16 bytes");
                }

                var plaintextLength = noiseMessage.Length - 16;
                var plaintext = this.strobeIn.RecvEncUnauthenticated(false, noiseMessage.Take(plaintextLength).ToArray());
                var ok = this.strobeIn.RecvMac(false, noiseMessage.Skip(plaintextLength).ToArray());

                if (!ok)
                {
                    throw new Exception("disco: cannot decrypt the payload");
                }

                // append to the input buffer
                this.inputBuffer = this.inputBuffer.Concat(plaintext).ToArray();

                // read whatever we can read
                var rest = data.Length - readSoFar;
                var restToRead = this.inputBuffer.Length > rest ? rest :(int)this.inputBuffer.Length ;
                this.inputBuffer.CopyTo(data, readSoFar);
                if (this.inputBuffer.Length > restToRead)
                {
                    this.inputBuffer = this.inputBuffer.Skip(readSoFar).ToArray();
                    return data.Length;
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

        private byte[] ReadFromUntil(TcpClient s, int n)
        {
            var result = new byte[n];

            s.Client.Receive(result, 0, n, SocketFlags.Partial);

            return result;
            //var offset = 0;

            //while (offset < n) {
            //    try
            //    {
            //        var m = s.Receive(result, offset, 1, SocketFlags.Partial);

            //        offset += m;

            //        if (offset == n)
            //        {
            //            break;
            //        }
            //    }
            //    catch (Exception)
            //    {
            //        return result;
            //    }
            //}
            //return result;
        }

        // Handshake runs the client or server handshake protocol if
        // it has not yet been run.
        // Most uses of this package need not call Handshake explicitly:
        // the first Read or Write will call it automatically.
        public void HandShake()
        {
            // Locking the handshakeMutex
            this.handshakeMutex.WaitOne();
            try
            {
                Strobe c1 = null;
                Strobe c2 = null;
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
                    remoteKeyPair = new KeyPair();
                    Array.Copy(this.config.RemoteKey, remoteKeyPair.PublicKey, this.config.RemoteKey.Length);
                }

                var handshakeState = DiscoOoooo.Initialize(
                    this.config.HandshakePattern,
                    this.IsClient,
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
                        byte[] bufToWrite = null;

                        if (handshakeState.MessagePatterns.Length <= 2)
                        {
                            (c1, c2) = handshakeState.WriteMessage(this.config.StaticPublicKeyProof, out bufToWrite);
                        }
                        else
                        {
                            (c1, c2) = handshakeState.WriteMessage(new byte[] { }, out bufToWrite);
                        }                        

                        // header (length)
                        var length = new byte[] { (byte)(bufToWrite.Length >> 8), (byte)(bufToWrite.Length % 256) };
                        // write
                        var dataToWrite = length.Concat(bufToWrite).ToArray();
                        this.SocketConnection.Client.Send(dataToWrite);
                    }
                    else
                    {
                        var bufHeader = this.ReadFromUntil(this.SocketConnection, 2);

                        var length = ((int)(bufHeader[0]) << 8) | (int)(bufHeader[1]);

                        if (length > Config.NoiseMessageLength)
                        {
                            throw new Exception("disco: Disco message received exceeds DiscoMessageLength");

                        }

                        var noiseMessage = ReadFromUntil(this.SocketConnection, length);

                        (c1, c2) = handshakeState.ReadMessage(noiseMessage, out receivedPayload);
                    }
                } while (c1 == null);

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
                    if (this.IsClient)
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
                return;
            }
            finally
            {
                this.handshakeMutex.ReleaseMutex();
            }
        }
    }
}

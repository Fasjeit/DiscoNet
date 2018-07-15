namespace DiscoNet
{
    using System;
    using System.Linq;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;

    using DiscoNet.Noise;

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

        // Authentication thingies
        private bool isRemoteAuthenticated { get; set; }

        // input/output
        private Strobe strobeIn { get; set; }

        private Strobe strobeOut { get; set; }

        private byte[] inputBuffer { get; set; }

        // half duplex
        private bool isHalfDuplex { get; set; }

        private Mutex halfDuplexLock { get; set; }

        // Write writes data to the connection.
        public int Write(byte[] data)
        {
            return 50;
        }

        public int Read(out byte[] data)
        {
            //            // read noise message from socket
            //            var noiseMessage = this.ReadFromUntil(this.SocketConnection, length);

            //            // decrypt
            //            if (length < 16)
            //            {
            //                throw new Exception("disco: the received payload is shorter 16 bytes");
            //            }

            //            /* // append to the input buffer
            //c.inputBuffer = append(c.inputBuffer, plaintext...)

            //// read whatever we can read
            //rest := len(b) - readSoFar
            //copy(b[readSoFar:], c.inputBuffer)
            //if len(c.inputBuffer) >= rest {
            //c.inputBuffer = c.inputBuffer[rest:]
            //return len(b), nil
            //}

            //// we haven't filled the buffer
            //readSoFar += len(c.inputBuffer)
            //c.inputBuffer = c.inputBuffer[:0]
            //return readSoFar, nil
            //*/
            //            var plaintextSize = noiseMessage.Length - 16;
            //            var plaintext = this.strobeIn.RecvEncUnauthenticated(false, noiseMessage.Take(plaintextSize).ToArray());
            //            var macCheckResult = this.strobeIn.RecvMac(false, noiseMessage.Skip(plaintextSize).ToArray());
            //            if (!macCheckResult)
            //            {
            //                throw new Exception("disco: cannot decrypt the payload");
            //            }

            //            // append to the input buffer
            //            this.inputBuffer = this.inputBuffer.Concat(plaintext).ToArray();
            //            // read whatever we can read
            data= Encoding.ASCII.GetBytes("hello");
            return 50;
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
                } while (c1 != null);

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

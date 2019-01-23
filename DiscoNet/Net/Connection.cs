namespace DiscoNet.Net
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    using System.IO.Pipes;
    using System.IO.Pipelines;

    using StrobeNet;

    /// <summary>
    /// Represents a secured connection
    /// </summary>
    public class Connection : IDisposable
    {
        private Config config;

        private readonly Mutex halfDuplexLock = new Mutex();

        private readonly Mutex handshakeMutex = new Mutex();

        private readonly Mutex inLock = new Mutex();

        private bool isClient;

        private readonly Mutex outLock = new Mutex();

        private readonly NetworkStream connectionStream;

        private bool handshakeComplite;

        private byte[] inputBuffer = { };

        // half duplex
        public bool IsHalfDuplex { get; private set; }

        // IsRemoteAuthenticated can be used to check if the remote peer 
        // has been properly authenticated.It serves no real purpose for 
        // the moment as the handshake will not go through if a peer is not 
        // properly authenticated in patterns where the peer needs to be authenticated.
        private bool isRemoteAuthenticated;

        /// <summary>
        /// Remote party static key
        /// </summary>
        public byte[] RemotePublicKey { get; private set; }

        // input/output
        private Strobe strobeIn;

        private Strobe strobeOut;

        /// <summary>
        /// Create Disco connection
        /// </summary>
        /// <param name="connectionStream">connection to use</param>
        public Connection(NetworkStream connectionStream)
        {
            this.connectionStream = connectionStream;
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
            if (this.IsHalfDuplex)
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
                    dataLen = dataLen > count - totalBytes ? count - totalBytes : dataLen;

                    // Encrypt
                    //var plaintext = new byte[dataLen];
                    //Array.Copy(data, offset, plaintext, 0, dataLen);
                    var ciphertext = this.strobeOut.SendEncUnauthenticated(false, data, offset, dataLen);


                    var mac = this.strobeOut.SendMac(false, Symmetric.TagSize);

                    //var ciphertextWithMac = new byte[ciphertext.Length + mac.Length];
                    //Array.Copy(ciphertext, 0, ciphertextWithMac, 0, ciphertext.Length);
                    //Array.Copy(mac, 0, ciphertextWithMac, ciphertext.Length, mac.Length);

                    // header (length)
                    var totalLength = ciphertext.Length + mac.Length;
                    var length = new[] { (byte)(totalLength >> 8), (byte)(totalLength % 256) };

                    // Send data
                    //var packet = new byte[length.Length + ciphertextWithMac.Length];
                    //Array.Copy(length, 0, packet, 0, length.Length);
                    //Array.Copy(ciphertextWithMac, 0, packet, length.Length, ciphertextWithMac.Length);

                    // len || ct|| mac
                    this.connectionStream.Write(length, 0, length.Length);
                    this.connectionStream.Write(ciphertext, 0, ciphertext.Length);
                    this.connectionStream.Write(mac, 0, mac.Length);

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
            if (this.IsHalfDuplex)
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
                //this.ProcessLinesAsync(this.connectionStream).GetAwaiter().GetResult();
                data = this.ProcessLinesAsync(this.connectionStream).GetAsyncEnumerator().Current;
                this.ProcessLinesAsync(this.connectionStream).GetAsyncEnumerator().MoveNextAsync().GetAwaiter().GetResult();
                //data = new byte[128];
                //return count > 128 ? 128 : count ;
                return data.Length;

                //// read whatever there is to read in the buffer
                //if (this.inputBuffer.Length > 0)
                //{
                //    var toRead = this.inputBuffer.Length > count ? count : this.inputBuffer.Length;
                //    Array.Copy(this.inputBuffer, 0, data, offset, toRead);
                //    if (this.inputBuffer.Length > count)
                //    {
                //        //this.inputBuffer = this.inputBuffer.Skip(count).ToArray();
                //        var newInputBuffer = new byte[this.inputBuffer.Length - count];
                //        Array.Copy(this.inputBuffer, count, newInputBuffer, 0, newInputBuffer.Length);
                //        this.inputBuffer = newInputBuffer;

                //        return count;
                //    }
                //    this.inputBuffer = new byte[] { };
                //    return toRead;
                //}

                //// read header from socket
                //var bufHeader = this.ReadFromUntil(this.connectionStream, 2);

                //var length = (bufHeader[0] << 8) | bufHeader[1];

                //if (length > Config.NoiseMessageLength)
                //{
                //    throw new Exception("disco: Disco message received exceeds DiscoMessageLength");
                //}

                //// read noise message from socket
                //var noiseMessage = this.ReadFromUntil(this.connectionStream, length);

                //// decrypt
                //if (length < Symmetric.TagSize)
                //{
                //    throw new Exception($"disco: the received payload is shorter {Symmetric.TagSize} bytes");
                //}

                //var plaintextLength = noiseMessage.Length - Symmetric.TagSize;
                ////var cipherText = new byte[plaintextLength];
                ////Array.Copy(noiseMessage, 0, cipherText, 0, plaintextLength);
                //var plaintext = this.strobeIn.RecvEncUnauthenticated(
                //    false,
                //    noiseMessage, 0, plaintextLength);

                //var macLen = noiseMessage.Length - plaintextLength;
                //var ok = this.strobeIn.RecvMac(false, noiseMessage, plaintextLength, macLen);

                //if (!ok)
                //{
                //    throw new Exception("disco: cannot decrypt the payload");
                //}

                //// append to the input buffer
                //var newInputBufferConcat = new byte[this.inputBuffer.Length + plaintext.Length];
                //Array.Copy(this.inputBuffer, 0, newInputBufferConcat, 0, this.inputBuffer.Length);
                //Array.Copy(plaintext, 0, newInputBufferConcat, this.inputBuffer.Length, plaintext.Length);
                //this.inputBuffer = newInputBufferConcat;
                ////this.inputBuffer = this.inputBuffer.Concat(plaintext).ToArray();

                //// read whatever we can read
                //var rest = count;
                //var restToRead = this.inputBuffer.Length > rest ? rest : this.inputBuffer.Length;
                //Array.Copy(this.inputBuffer, 0, data, offset, restToRead);
                //if (this.inputBuffer.Length > restToRead)
                //{
                //    var newBuffer = new byte[this.inputBuffer.Length - restToRead];
                //    Array.Copy(this.inputBuffer, restToRead, newBuffer, 0, newBuffer.Length);
                //    this.inputBuffer = newBuffer;
                //    //this.inputBuffer = this.inputBuffer.Skip(restToRead).ToArray();

                //    return count;
                //}

                //// we haven't filled the buffer
                //this.inputBuffer = new byte[] { };

                //return restToRead;
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
        /// <param name="count">Number of bytes</param>
        /// <returns>Read bytes</returns>
        private byte[] ReadFromUntil(NetworkStream connection, int count)
        {
            var buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = connection.Read(buffer, offset, count - offset);
                if (read == 0)
                    throw new System.IO.EndOfStreamException();
                offset += read;
            }

            return buffer;
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

                handshakeState = DiscoHelper.InitializeDisco(
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
                        this.connectionStream.Write(dataToWrite, 0, dataToWrite.Length);
                    }
                    else
                    {
                        var bufHeader = this.ReadFromUntil(this.connectionStream, 2);

                        var length = (bufHeader[0] << 8) | bufHeader[1];

                        if (length > Config.NoiseMessageLength)
                        {
                            throw new Exception("disco: Disco message received exceeds DiscoMessageLength");
                        }

                        var noiseMessage = this.ReadFromUntil(this.connectionStream, length);

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

                        this.isRemoteAuthenticated = true;
                        this.RemotePublicKey = handshakeState.Rs.PublicKey;
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
                    this.IsHalfDuplex = true;
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
            this.connectionStream?.Close();
            this.connectionStream?.Dispose();
        }

        /// <summary>
        /// Authentice as Server with Disco
        /// </summary>
        /// <param name="config">Disco config</param>
        public void AuthenticateAsServer(Config config)
        {
            this.config = config;
            this.isClient = false;

            Connection.CheckRequirements(this.isClient, config);

            this.HandShake();
        }

        /// <summary>
        /// Authentice as Client with Disco
        /// </summary>
        /// <param name="config">Disco config</param>
        public void AuthenticateAsClient(Config config)
        {
            this.config = config;
            this.isClient = true;

            Connection.CheckRequirements(this.isClient, config);

            this.HandShake();
        }


        /// <summary>
        /// Check Disco configuration requirements
        /// </summary>
        /// <param name="isClient">Is client connection</param>
        /// <param name="config">Disco config</param>
        private static void CheckRequirements(bool isClient, Config config)
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

            if (ht == NoiseHandshakeType.NoiseNNpsk2 && config.PreSharedKey.Length != Symmetric.PskKeySize)
            {
                throw new Exception($"noise: a {Symmetric.PskKeySize}-byte pre-shared key needs to be passed as noise Config");
            }
        }

        ///
        ///
        /// 

        private async Task<byte[]> DecryptNoiseMessageAsync(ReadOnlySequence<byte> noiseMessage)
        {
            var plaintextLength = (int)noiseMessage.Length - Symmetric.TagSize;
            var cipherText = noiseMessage.Slice(0, plaintextLength);
            var plaintext = this.strobeIn.RecvEncUnauthenticated(false, cipherText.ToArray());

            var macLen = noiseMessage.Length - plaintextLength;
            var mac = noiseMessage.Slice(plaintextLength, macLen);
            var ok = this.strobeIn.RecvMac(false, mac.ToArray());

            if (!ok)
            {
                throw new Exception("disco: cannot decrypt the payload");
            }

            return plaintext;
        }

        async IAsyncEnumerable<byte[]> ProcessLinesAsync(NetworkStream socket)
        {
            var pipe = new Pipe();
            await this.FillPipeAsync(socket, pipe.Writer);

            var enumerator = this.ReadPipeAsync(pipe.Reader).GetAsyncEnumerator();
            yield return enumerator.Current;
            await enumerator.MoveNextAsync();

        }

        async Task FillPipeAsync(NetworkStream socket, PipeWriter writer)
        {
            const int MinimumBufferSize = 512;

            while (true)
            {
                // Allocate at least 512 bytes from the PipeWriter
                Memory<byte> memory = writer.GetMemory(MinimumBufferSize);
                try
                {
                    int bytesRead = await socket.ReadAsync(memory);
                    if (bytesRead == 0)
                    {
                        break;
                    }
                    // Tell the PipeWriter how much was read from the Socket
                    writer.Advance(bytesRead);
                }
                catch (Exception ex)
                {
                    throw ex;
                    //LogError(ex);
                    break;
                }

                // Make the data available to the PipeReader
                FlushResult result = await writer.FlushAsync();

                if (result.IsCompleted)
                {
                    break;
                }
            }

            // Tell the PipeReader that there's no more data coming
            writer.Complete();
        }

        private async IAsyncEnumerable<byte[]> ReadPipeAsync(PipeReader reader)
        {
            while (true)
            {
                ReadResult result = await reader.ReadAsync();

                ReadOnlySequence<byte> buffer = result.Buffer;

                do
                {
                    var bufHeader = buffer.Slice(0, 2).ToArray();
                    var length = (bufHeader[0] << 8) | bufHeader[1];

                    if (length > Config.NoiseMessageLength)
                    {
                        throw new Exception("disco: Disco message received exceeds DiscoMessageLength");
                    }

                    var toRead = length > buffer.Length - 2 ? buffer.Length - 2 : length;

                    // Process the line
                    yield return await this.DecryptNoiseMessageAsync(buffer.Slice(2, toRead));

                    // Skip the message + length (2 bytes)
                    buffer = buffer.Slice(2 + toRead);
                }
                while (!buffer.IsEmpty);

                // Tell the PipeReader how much of the buffer we have consumed
                reader.AdvanceTo(buffer.Start, buffer.End);

                // Stop reading if there's no more data coming
                if (result.IsCompleted)
                {
                    break;
                }
            }

            // Mark the PipeReader as complete
            reader.Complete();
        }
    }
}

//// tmp for vs preview 1
//namespace System.Threading.Tasks
//{
//    using System.Runtime.CompilerServices;
//    using System.Threading.Tasks.Sources;

//    internal struct ManualResetValueTaskSourceLogic<TResult>
//    {
//        private ManualResetValueTaskSourceCore<TResult> _core;
//        public ManualResetValueTaskSourceLogic(IStrongBox<ManualResetValueTaskSourceLogic<TResult>> parent) : this() { }
//        public short Version => _core.Version;
//        public TResult GetResult(short token) => _core.GetResult(token);
//        public ValueTaskSourceStatus GetStatus(short token) => _core.GetStatus(token);
//        public void OnCompleted(Action<object> continuation, object state, short token, ValueTaskSourceOnCompletedFlags flags) => _core.OnCompleted(continuation, state, token, flags);
//        public void Reset() => _core.Reset();
//        public void SetResult(TResult result) => _core.SetResult(result);
//        public void SetException(Exception error) => _core.SetException(error);
//    }
//}

//namespace System.Runtime.CompilerServices
//{
//    internal interface IStrongBox<T> { ref T Value { get; } }
}

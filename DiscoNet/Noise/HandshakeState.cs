namespace DiscoNet.Noise
{
    using System;
    using System.Linq;

    using DiscoNet.Noise.Enums;
    using DiscoNet.Noise.Pattern;

    using StrobeNet;

    /// <summary>
    /// Noise handshake state
    /// </summary>
    public class HandshakeState : IDisposable
    {
        /// <summary>
        /// SymmetricState object
        /// </summary>
        public SymmetricState SymmetricState { get; internal set; }

        /// <summary>
        /// The local static key pair
        /// </summary>
        public KeyPair S { get; internal set; }

        /// <summary>
        /// The local ephemeral key pair
        /// </summary>
        public KeyPair E { get; internal set; }

        /// <summary>
        /// The remote party's static public key
        /// </summary>
        public KeyPair Rs { get; internal set; }

        /// <summary>
        /// The remote party's ephemeral public key
        /// </summary>
        public KeyPair Re { get; internal set; }

        /// <summary>
        /// Indicating the initiator or responder role.
        /// </summary>
        public bool Initiator { get; internal set; }

        /// <summary>
        /// A sequence of message pattern. Each message pattern is a sequence
        /// of tokens from the set ("e", "s", "ee", "es", "se", "ss")
        /// </summary>
        public MessagePattern[] MessagePatterns { get; internal set; }

        /// <summary>
        /// indicating if the role of the peer is to WriteMessage
        /// or ReadMessage
        /// </summary>
        public bool ShouldWrite { get; internal set; }

        /// <summary>
        /// Pre-shared key
        /// </summary>
        public byte[] Psk { get; internal set; }

        /// <summary>
        /// For test vectors
        /// </summary>
        internal KeyPair DebugEphemeral { get; set; }

        /// <summary>
        /// Dispose and free resources
        /// </summary>
        public void Dispose()
        {
            this.S?.Dispose();
            this.Rs?.Dispose();
            this.E?.Dispose();
            this.Re?.Dispose();
            this.DebugEphemeral?.Dispose();
        }

        /// <summary>
        /// Write payload with handshake message using current state
        /// </summary>
        /// <param name="payload">payload to write</param>
        /// <param name="messageBuffer">output message buffer</param>
        /// <returns>Tuple of strobe state for initiator and responder</returns>
        internal (Strobe initiatorState, Strobe responderState) WriteMessage(byte[] payload, out byte[] messageBuffer)
        {
            Strobe initiatorState = null;
            Strobe responderState = null;
            messageBuffer = new byte[] { };

            // is it our turn to write?
            if (!this.ShouldWrite)
            {
                throw new Exception("disco: unexpected call to WriteMessage should be ReadMessage");
            }

            // do we have a token to process?
            if (this.MessagePatterns.Length == 0 || this.MessagePatterns[0].Tokens.Count == 0)
            {
                throw new Exception("disco: no more tokens or message patterns to write");
            }

            // process the patterns
            foreach (var pattern in this.MessagePatterns[0])
            {
                switch (pattern)
                {
                    case Tokens.TokenE:
                    {
                        // debug
                        if (this.DebugEphemeral != null)
                        {
                            this.E = this.DebugEphemeral;
                        }
                        else
                        {
#if DEBUG_DETERMINISTIC
                            this.E = Asymmetric.GenerateKeyPair(new byte[Asymmetric.DhLen]);
#else
                            this.E = Asymmetric.GenerateKeyPair();
#endif
                        }

                        messageBuffer = messageBuffer.Concat(this.E.PublicKey).ToArray();
                        this.SymmetricState.MixHash(this.E.PublicKey);
                        if (this.Psk?.Length > 0)
                        {
                            this.SymmetricState.MixKey(this.E.PublicKey);
                        }

                        break;
                    }
                    case Tokens.TokenS:
                    {
                        var encrypted = this.SymmetricState.EncryptAndHash(this.S.PublicKey);
                        messageBuffer = messageBuffer.Concat(encrypted).ToArray();
                        break;
                    }
                    case Tokens.TokenEE:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Re.PublicKey));
                        break;
                    }
                    case Tokens.TokenES:
                    {
                        if (this.Initiator)
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Rs.PublicKey));
                        }
                        else
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Re.PublicKey));
                        }

                        break;
                    }
                    case Tokens.TokenSE:
                    {
                        if (this.Initiator)
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Re.PublicKey));
                        }
                        else
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Rs.PublicKey));
                        }

                        break;
                    }
                    case Tokens.TokenSS:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Rs.PublicKey));
                        break;
                    }
                    case Tokens.TokenPsk:
                    {
                        this.SymmetricState.MixHash(this.Psk);
                        break;
                    }
                    default:
                    {
                        throw new Exception("Disco: token not recognized");
                    }
                }
            }

            // Appends EncryptAndHash(payload) to the buffer
            var ciphertext = this.SymmetricState.EncryptAndHash(payload);
            messageBuffer = messageBuffer.Concat(ciphertext).ToArray();

            // are there more message patterns to process?
            if (this.MessagePatterns.Length == 1)
            {
                this.MessagePatterns = null;
                // If there are no more message patterns returns two new CipherState objects
                (initiatorState, responderState) = this.SymmetricState.Split();
            }
            else
            {
                // remove the pattern from the messagePattern
                this.MessagePatterns = this.MessagePatterns.Skip(1).ToArray();
            }

            // change the direction
            this.ShouldWrite = false;

            return (initiatorState, responderState);
        }

        /// <summary>
        /// Read handshake message and output payload
        /// </summary>
        /// <param name="message">Noise message</param>
        /// <param name="payloadBuffer">payload buffer</param>
        /// <returns>Tuple of strobe state for initiator and responder</returns>
        public (Strobe initiatorState, Strobe responderState) ReadMessage(byte[] message, out byte[] payloadBuffer)
        {
            Strobe initiatorState = null;
            Strobe responderState = null;
            payloadBuffer = new byte[] { };

            // is it our turn to read?
            if (this.ShouldWrite)
            {
                throw new Exception("disco: unexpected call to ReadMessage should be WriteMessage");
            }

            // do we have a token to process?
            if (this.MessagePatterns.Length == 0 || this.MessagePatterns[0].Tokens.Count == 0)
            {
                throw new Exception("disco: no more tokens or message patterns to write");
            }

            // process the patterns
            var offset = 0;

            foreach (var pattern in this.MessagePatterns[0])
            {
                switch (pattern)
                {
                    case Tokens.TokenE:
                    {
                        if (message.Length - offset < Asymmetric.DhLen)
                        {
                            throw new Exception("disco: the received ephemeral key is to short");
                        }

                        this.Re = new KeyPair { PublicKey = message.Skip(offset).Take(Asymmetric.DhLen).ToArray() };
                        offset += Asymmetric.DhLen;
                        this.SymmetricState.MixHash(this.Re.PublicKey);
                        if (this.Psk?.Length > 0)
                        {
                            this.SymmetricState.MixKey(this.Re.PublicKey);
                        }

                        break;
                    }
                    case Tokens.TokenS:
                    {
                        var tagLen = 0;
                        if (this.SymmetricState.IsKeyed)
                        {
                            tagLen = Symmetric.TagSize;
                        }

                        if (message.Length - offset < Asymmetric.DhLen + tagLen)
                        {
                            throw new Exception("disco: the received static key is to short");
                        }

                        var decrypted = this.SymmetricState.DecryptAndHash(
                            message.Skip(offset).Take(Asymmetric.DhLen + tagLen).ToArray());

                        // if we already know the remote static, compare
                        this.Rs = new KeyPair { PublicKey = decrypted };
                        offset += Asymmetric.DhLen + tagLen;
                        break;
                    }
                    case Tokens.TokenEE:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Re.PublicKey));
                        break;
                    }
                    case Tokens.TokenES:
                    {
                        if (this.Initiator)
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Rs.PublicKey));
                        }
                        else
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Re.PublicKey));
                        }

                        break;
                    }
                    case Tokens.TokenSE:
                    {
                        if (this.Initiator)
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Re.PublicKey));
                        }
                        else
                        {
                            this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Rs.PublicKey));
                        }

                        break;
                    }
                    case Tokens.TokenSS:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Rs.PublicKey));
                        break;
                    }
                    case Tokens.TokenPsk:
                    {
                        this.SymmetricState.MixKeyAndHash(this.Psk);
                        break;
                    }
                }
            }

            // Appends decrpyAndHash(payload) to the buffer
            var plaintext = this.SymmetricState.DecryptAndHash(message.Skip(offset).ToArray());

            payloadBuffer = payloadBuffer.Concat(plaintext).ToArray();

            // remove the pattern from the messagePattern
            if (this.MessagePatterns.Length == 1)
            {
                this.MessagePatterns = null;
                // If there are no more message patterns returns two new CipherState object
                (initiatorState, responderState) = this.SymmetricState.Split();
            }
            else
            {
                this.MessagePatterns = this.MessagePatterns.Skip(1).ToArray();
            }

            // change the direction
            this.ShouldWrite = true;

            return (initiatorState, responderState);
        }

        /// <summary>
        /// Destructor
        /// </summary>
        ~HandshakeState()
        {
            this.Dispose();
        }
    }
}
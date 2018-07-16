namespace DiscoNet.Noise
{
    using System;
    using System.Linq;
    using DiscoNet.Noise.Pattern;

    using StrobeNet;

    public class HandshakeState : IDisposable
    {
        /// <summary>
        /// SymmetricState object
        /// </summary>
        public SymmetricState SymmetricState { get; set; }

        /// <summary>
        /// The local static key pair
        /// </summary>
        public KeyPair S { get; set; } = new KeyPair();

        /// <summary>
        /// The local ephemeral key pair
        /// </summary>
        public KeyPair E { get; set; } = new KeyPair();

        /// <summary>
        /// The remote party's static public key
        /// </summary>
        public KeyPair Rs { get; set; } = new KeyPair();

        /// <summary>
        /// The remote party's ephemeral public key
        /// </summary>
        public KeyPair Re { get; set; } = new KeyPair();

        /// <summary>
        /// Indicating the initiator or responder role.
        /// </summary>
        public bool Initiator { get; set; }

        /// <summary>
        /// A sequence of message pattern. Each message pattern is a sequence
        /// of tokens from the set ("e", "s", "ee", "es", "se", "ss")
        /// </summary>
        public MessagePattern[] MessagePatterns { get; set; }

        /// <summary>
        /// indicating if the role of the peer is to WriteMessage
        /// or ReadMessage
        /// </summary>
        public bool ShouldWrite { get; set; }

        /// <summary>
        /// Pre-shared key
        /// </summary>
        public byte[] Psk { get; set; }

        /// <summary>
        /// For test vectors
        /// </summary>
        public KeyPair DebugEphemeral { get; set; }

        public (Strobe initiatorState, Strobe responderState) WriteMessage(byte[] payload, out byte[] messageBuffer)
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
                    case Enums.Tokens.TokenE:
                    {
                        // debug
                        if (this.DebugEphemeral != null)
                        {
                            this.E = this.DebugEphemeral;
                        }
                        else
                        {
                            //#Q_return randomness #E
                            this.E = Asymmetric.GenerateKeyPair();
                        }

                        messageBuffer = messageBuffer.Concat(this.E.PublicKey).ToArray();
                        this.SymmetricState.MixHash(this.E.PublicKey);
                        if (this.Psk?.Length > 0)
                        {
                            this.SymmetricState.MixKey(this.E.PublicKey);
                        }
                        break;
                    }
                    case Enums.Tokens.TokenS:
                    {
                        var encrypted = this.SymmetricState.EncryptAndHash(this.S.PublicKey);
                        messageBuffer = messageBuffer.Concat(encrypted).ToArray();
                        break;
                    }
                    case Enums.Tokens.TokenEe:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Re.PublicKey));
                        break;
                    }
                    case Enums.Tokens.TokenEs:
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
                    case Enums.Tokens.TokenSe:
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
                    case Enums.Tokens.TokenSs:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Rs.PublicKey));
                        break;
                    }
                    case Enums.Tokens.TokenPsk:
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

        // ReadMessage takes a byte sequence containing a Noise handshake message,
        // and a payload_buffer to write the message's plaintext payload into.
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
                    case Enums.Tokens.TokenE:
                    {
                        if (message.Length - offset < Asymmetric.DhLen)
                        {
                            throw new Exception("disco: the received ephemeral key is to short");
                        }

                        this.Re.PublicKey = message.Skip(offset).Take(Asymmetric.DhLen).ToArray();
                        offset += Asymmetric.DhLen;
                        this.SymmetricState.MixHash(this.Re.PublicKey);
                        if (this.Psk?.Length > 0)
                        {
                            this.SymmetricState.MixKey(this.Re.PublicKey);
                        }

                        break;
                    }
                    case Enums.Tokens.TokenS:
                    {
                        var tagLen = 0;
                        if (this.SymmetricState.IsKeyed)
                        {
                            tagLen = 16;
                        }

                        if (message.Length - offset < Asymmetric.DhLen + tagLen)
                        {
                            throw new Exception("disco: the received static key is to short");
                        }

                        var decrypted = this.SymmetricState.DecryptAndHash(
                            message.Skip(offset).Take(Asymmetric.DhLen + tagLen).ToArray());

                        // if we already know the remote static, compare
                        this.Rs.PublicKey = decrypted;
                        offset += Asymmetric.DhLen + tagLen;
                        break;
                    }
                    case Enums.Tokens.TokenEe:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.E, this.Re.PublicKey));
                        break;
                    }
                    case Enums.Tokens.TokenEs:
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
                    case Enums.Tokens.TokenSe:
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
                    case Enums.Tokens.TokenSs:
                    {
                        this.SymmetricState.MixKey(Asymmetric.Dh(this.S, this.Rs.PublicKey));
                        break;
                    }
                    case Enums.Tokens.TokenPsk:
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

        public void Dispose()
        {
            this.S?.Dispose();
            this.Rs?.Dispose();
            this.E?.Dispose();
            this.Re?.Dispose();
        }

        ~HandshakeState()
        {
            this.Dispose();
        }
    }
}

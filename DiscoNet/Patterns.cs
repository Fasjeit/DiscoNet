namespace DiscoNet
{
    using System.Collections;
    using System.Collections.Generic;

    internal enum NoiseHandshakeType
    {
        /// <summary>
        /// Noise_N is a one-way pattern where a client can send
        /// data to a server with a known static key. The server
        /// can only receive data and cannot reply back.
        /// </summary>
        NoiseN,

        /// <summary>
        /// Noise_K is a one-way pattern where a client can send
        /// data to a server with a known static key. The server
        /// can only receive data and cannot reply back. The server
        /// authenticates the client via a known key.
        /// </summary>
        NoiseK,

        /// <summary>
        /// Noise_X is a one-way pattern where a client can send
        /// data to a server with a known static key. The server
        /// can only receive data and cannot reply back. The server
        /// authenticates the client via a key transmitted as part
        /// of the handshake.
        //// </summary>
        NoiseX,

        /// <summary>
        /// Noise_KK is a pattern where both the client static key and the
        ///     server static key are known.
        /// </summary>
        NoiseKK,

        /// <summary>
        /// Noise_NX is a "HTTPS"-like pattern where the client is
        /// not authenticated, and the static public key of the server
        /// is transmitted during the handshake. It is the responsability of the client to validate the received key properly.
        /// </summary>
        NoiseNX,

        /// <summary>
        /// Noise_NK is a "Public Key Pinning"-like pattern where the client
        /// is not authenticated, and the static public key of the server
        /// is already known.
        /// </summary>
        NoiseNK,

        /// <summary>
        /// Noise_XX is a pattern where both static keys are transmitted.
        /// It is the responsability of the server and of the client to
        /// validate the received keys properly.
        /// </summary>
        NoiseXX,

        // Not documented
        NoiseKX,

        NoiseXK,

        NoiseIK,

        NoiseIX,

        NoiseNNpsk2,

        // Not implemented
        NoiseNN,

        NoiseKN,

        NoiseXN,

        NoiseIN
    }

    internal enum Tokens
    {
        TokenE,

        TokenS,

        TokenEs,

        TokenSe,

        TokenSS,

        TokenEe,

        tokenPsk
    }

    internal class MessagePattern : IEnumerable<Tokens>
    {
        public List<Tokens> Tokens { get; set; }

        public IEnumerator<Tokens> GetEnumerator()
        {
            return this.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.Tokens.GetEnumerator();
        }

        public void Add(Tokens token)
        {
            this.Tokens.Add(token);
        }
    }

    internal class HandshakePattern
    {
        public string Name { get; set; }

        public MessagePattern[] PreMessagePatterns { get; set; }

        public MessagePattern[] MessagePatterns { get; set; }
    }


    // TODO: add more patterns
    internal class Patterns
    {
        // 7.2. One-way patterns

        private static HandshakePattern NoiseN = new HandshakePattern
        {
            Name = "N",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern { Tokens.TokenS }
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs }
            }
        };

        /*
		K(s, rs):
		  -> s
		  <- s
		  ...
		  -> e, es, ss
	    */

        private static HandshakePattern NoiseX = new HandshakePattern
        {
            Name = "X",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern { Tokens.TokenS }
            },
            MessagePatterns = new[]
            {
                new MessagePattern
                {
                    // →
                    Tokens.TokenE,
                    Tokens.TokenEs,
                    Tokens.TokenS,
                    Tokens.TokenSS
                }
            }
        };

        // 7.3. Interactive patterns

        private static HandshakePattern NoiseKK = new HandshakePattern
        {
            Name = "KK",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenS },
                // ←
                new MessagePattern { Tokens.TokenS }
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs, Tokens.TokenSS },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenSe }
            }
        };

        private static HandshakePattern NoiseNx = new HandshakePattern
        {
            Name = "NX",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern()
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenS, Tokens.TokenEs }
            }
        };

        private static HandshakePattern NoiseNk = new HandshakePattern
        {
            Name = "NK",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern { Tokens.TokenS }
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs }
            }
        };

        private static HandshakePattern NoiseXx = new HandshakePattern
        {
            Name = "XX",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern()
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenS, Tokens.TokenEs },
                // →
                new MessagePattern { Tokens.TokenS, Tokens.TokenSe }
            }
        };

        /*
			KX(s, rs):
		      -> s
		      ...
		      -> e
		      <- e, ee, se, s, es
	    */

        private static HandshakePattern NoiseKx = new HandshakePattern
        {
            Name = "KX",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenS },
                // ←
                new MessagePattern()
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenSe, Tokens.TokenS, Tokens.TokenEs }
            }
        };

        /*
			XK(s, rs):
		  <- s
		  ...
		  -> e, es
		  <- e, ee
		  -> s, se
	    */

        private static HandshakePattern NoiseXk = new HandshakePattern
        {
            Name = "XK",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern { Tokens.TokenS }
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe },
                // →
                new MessagePattern { Tokens.TokenS, Tokens.TokenSe }
            }
        };

        /*
		IK(s, rs):
		<- s
		...
		-> e, es, s, ss
		<- e, ee, se
	    */

        private static HandshakePattern NoiseIk = new HandshakePattern
        {
            Name = "IK",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern { Tokens.TokenS }
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs, Tokens.TokenS, Tokens.TokenSS },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenSe }
            }
        };

        /*
		IX(s, rs):
		 -> e, s
		 <- e, ee, se, s, es
	    */

        private static HandshakePattern NoiseIx = new HandshakePattern
        {
            Name = "IX",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern()
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE, Tokens.TokenS },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenS, Tokens.TokenSe }
            }
        };

        /*
		NNpsk2():
		  -> e
		  <- e, ee, psk
	    */

        private static HandshakePattern NoiseNnPsk2 = new HandshakePattern
        {
            Name = "NNpsk2",
            PreMessagePatterns = new[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern()
            },
            MessagePatterns = new[]
            {
                // →
                new MessagePattern { Tokens.TokenE },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.tokenPsk }
            }
        };
    }
}
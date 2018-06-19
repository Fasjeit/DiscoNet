using System.Collections;
using System.Collections.Generic;

namespace DiscoNet
{
    enum NoiseHandshakeType
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
        /// server static key are known.
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
        NoiseIN,
    }

    enum Tokens
    {
        TokenE,

        TokenS,

        TokenEs,

        TokenSe,

        TokenSS,

        TokenEe,

        tokenPsk,
    }

    class MessagePattern : IEnumerable<Tokens>
    {
        public List<Tokens> Tokens { get; set; }

        public IEnumerator<Tokens> GetEnumerator()
        {
            return GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return Tokens.GetEnumerator();
        }

        public void Add(Tokens token)
        {
            Tokens.Add(token);
        }
    };

    class HandshakePattern
    {
        public string Name { get; set; }

        public MessagePattern[] PreMessagePatterns { get; set; }

        public MessagePattern[] MessagePatterns { get; set; }
    }

    class Patterns
    {
        // 7.2. One-way patterns

        static HandshakePattern NoiseN = new HandshakePattern()
        {
            Name = "N",
            PreMessagePatterns = new MessagePattern[]
            {
                // →
                new MessagePattern(), 
                // ←
                new MessagePattern() { Tokens.TokenS },
            },
            MessagePatterns = new MessagePattern[]
            {
                // →
                new MessagePattern() {Tokens.TokenE, Tokens.TokenEs },
            },
        };

        /*
		K(s, rs):
		  -> s
		  <- s
		  ...
		  -> e, es, ss
	    */

        static HandshakePattern NoiseX = new HandshakePattern()
        {
            Name = "X",
            PreMessagePatterns = new MessagePattern[]
            {
                // →
                new MessagePattern(),
                // ←
                new MessagePattern(){ Tokens.TokenS },
            },
            MessagePatterns = new MessagePattern[]
            {
                new MessagePattern()
                {
                    // →
                    Tokens.TokenE, Tokens.TokenEs, Tokens.TokenS, Tokens.TokenSS
                },
            }
        };


        // 7.3. Interactive patterns

        static HandshakePattern NoiseKK = new HandshakePattern()
        {
            Name = "KK",
            PreMessagePatterns = new MessagePattern[]
            {
                // →
                new MessagePattern() {Tokens.TokenS },
                // ←
                new MessagePattern() {Tokens.TokenS },
            },
            MessagePatterns = new MessagePattern[]
            {
                // →
                new MessagePattern() { Tokens.TokenE, Tokens.TokenEs, Tokens.TokenSS },
                // ←
                new MessagePattern() { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenSe },
            },
        };

        static HandshakePattern NoiseNx = new HandshakePattern()
        {
            Name = "NX",
            PreMessagePatterns = new MessagePattern[]
            {
                new MessagePattern(),
                new MessagePattern(),
            },
            MessagePatterns = new MessagePattern[]
            {
                 new MessagePattern() {Tokens.TokenE },
                 new MessagePattern() {Tokens.TokenE, Tokens.TokenEe, Tokens.TokenS, Tokens.TokenEs },
            }
        };
        //#Q_ more patterns
    }
}

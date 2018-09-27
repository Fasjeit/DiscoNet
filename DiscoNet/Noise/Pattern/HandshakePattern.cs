namespace DiscoNet.Noise.Pattern
{
    using System;
    using System.Collections.Generic;

    using DiscoNet.Noise.Enums;

    internal class HandshakePattern
    {
        private static readonly Dictionary<NoiseHandshakeType, HandshakePattern> PatternDictionary =
            new Dictionary<NoiseHandshakeType, HandshakePattern>();

        // 7.2. One-way patterns

        private static HandshakePattern NoiseN = new HandshakePattern(NoiseHandshakeType.NoiseN)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenES }
            }
        };

        /*
		K(s, rs):
		  -> s
		  <- s
		  ...
		  -> e, es, ss
	    */

        private static HandshakePattern NoiseX = new HandshakePattern(NoiseHandshakeType.NoiseX)
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
                    Tokens.TokenES,
                    Tokens.TokenS,
                    Tokens.TokenSS
                }
            }
        };

        // 7.3. Interactive patterns

        private static HandshakePattern NoiseKK = new HandshakePattern(NoiseHandshakeType.NoiseKK)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenES, Tokens.TokenSS },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE, Tokens.TokenSE }
            }
        };

        private static HandshakePattern NoiseNX = new HandshakePattern(NoiseHandshakeType.NoiseNX)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE, Tokens.TokenS, Tokens.TokenES }
            }
        };

        private static HandshakePattern NoiseNK = new HandshakePattern(NoiseHandshakeType.NoiseNK)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenES },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE }
            }
        };

        private static HandshakePattern NoiseXX = new HandshakePattern(NoiseHandshakeType.NoiseXX)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE, Tokens.TokenS, Tokens.TokenES },
                // →
                new MessagePattern { Tokens.TokenS, Tokens.TokenSE }
            }
        };

        /*
			KX(s, rs):
		      -> s
		      ...
		      -> e
		      <- e, ee, se, s, es
	    */

        private static HandshakePattern NoiseKX = new HandshakePattern(NoiseHandshakeType.NoiseKX)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE, Tokens.TokenSE, Tokens.TokenS, Tokens.TokenES }
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

        private static HandshakePattern NoiseXK = new HandshakePattern(NoiseHandshakeType.NoiseXK)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenES },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE },
                // →
                new MessagePattern { Tokens.TokenS, Tokens.TokenSE }
            }
        };

        /*
		IK(s, rs):
		<- s
		...
		-> e, es, s, ss
		<- e, ee, se
	    */

        private static HandshakePattern NoiseIK = new HandshakePattern(NoiseHandshakeType.NoiseIK)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenES, Tokens.TokenS, Tokens.TokenSS },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE, Tokens.TokenSE }
            }
        };

        /*
		IX(s, rs):
		 -> e, s
		 <- e, ee, se, s, es
	    */

        private static HandshakePattern NoiseIX = new HandshakePattern(NoiseHandshakeType.NoiseIX)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE, Tokens.TokenS, Tokens.TokenSE }
            }
        };

        /*
		NNpsk2():
		  -> e
		  <- e, ee, psk
	    */

        private static HandshakePattern NoiseNNPsk2 = new HandshakePattern(NoiseHandshakeType.NoiseNNpsk2)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEE, Tokens.TokenPsk }
            }
        };

        internal string Name { get; private set; }

        internal MessagePattern[] PreMessagePatterns { get; private set; }

        internal MessagePattern[] MessagePatterns { get; private set; }

        private HandshakePattern(NoiseHandshakeType pattern)
        {
            if (HandshakePattern.PatternDictionary.ContainsKey(pattern))
            {
                throw new ArgumentException("pattern of the same type is already exits!");
            }

            HandshakePattern.PatternDictionary.Add(pattern, this);
        }

        internal static HandshakePattern GetPattern(NoiseHandshakeType noiseType)
        {
            if (!HandshakePattern.PatternDictionary.TryGetValue(noiseType, out var result))
            {
                throw new ArgumentException("pattern of the same type is not exits!");
            }

            return result;
        }
    }
}
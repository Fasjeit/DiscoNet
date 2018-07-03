namespace DiscoNet.Noise.Pattern
{
    using System;
    using System.Collections.Generic;

    using DiscoNet.Noise.Enums;

    internal class HandshakePattern
    {
        private static Dictionary<NoiseHandshakeType, HandshakePattern> PatternDictionary =
            new Dictionary<NoiseHandshakeType, HandshakePattern>();

        internal string Name { get; set; }

        internal MessagePattern[] PreMessagePatterns { get; set; }

        internal MessagePattern[] MessagePatterns { get; set; }

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
                    Tokens.TokenEs,
                    Tokens.TokenS,
                    Tokens.TokenSs
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs, Tokens.TokenSs },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenSe }
            }
        };

        private static HandshakePattern NoiseNx = new HandshakePattern(NoiseHandshakeType.NoiseNX)
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

        private static HandshakePattern NoiseNk = new HandshakePattern(NoiseHandshakeType.NoiseNK)
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

        private static HandshakePattern NoiseXx = new HandshakePattern(NoiseHandshakeType.NoiseXX)
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

        private static HandshakePattern NoiseKx = new HandshakePattern(NoiseHandshakeType.NoiseKX)
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

        private static HandshakePattern NoiseXk = new HandshakePattern(NoiseHandshakeType.NoiseXK)
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

        private static HandshakePattern NoiseIk = new HandshakePattern(NoiseHandshakeType.NoiseIK)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs, Tokens.TokenS, Tokens.TokenSs },
                // ←
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenSe }
            }
        };

        /*
		IX(s, rs):
		 -> e, s
		 <- e, ee, se, s, es
	    */

        private static HandshakePattern NoiseIx = new HandshakePattern(NoiseHandshakeType.NoiseIX)
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

        private static HandshakePattern NoiseNnPsk2 = new HandshakePattern(NoiseHandshakeType.NoiseNNpsk2)
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenPsk }
            }
        };
    }
}
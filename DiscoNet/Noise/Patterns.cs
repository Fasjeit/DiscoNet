namespace DiscoNet.Noise
{
    using System.Collections;
    using System.Collections.Generic;

    using DiscoNet.Noise.Enums;

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
                    Tokens.TokenSs
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEs, Tokens.TokenSs },
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
                new MessagePattern { Tokens.TokenE, Tokens.TokenEe, Tokens.TokenPsk }
            }
        };
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
}
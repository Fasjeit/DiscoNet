namespace DiscoNet.Noise.Pattern
{
    using System.Collections;
    using System.Collections.Generic;

    using DiscoNet.Noise.Enums;

    /// <inheritdoc />
    /// <summary>
    /// Noise message pattern
    /// </summary>
    public class MessagePattern : IEnumerable<Tokens>
    {
        /// <summary>
        /// Tokens, representing the pattern
        /// </summary>
        public List<Tokens> Tokens { get; } = new List<Tokens>();

        internal MessagePattern()
        {
        }

        /// <summary>
        /// Get enumerator
        /// </summary>
        /// <returns></returns>
        public IEnumerator<Tokens> GetEnumerator()
        {
            return this.Tokens.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.Tokens.GetEnumerator();
        }

        internal void Add(Tokens token)
        {
            this.Tokens.Add(token);
        }
    }
}
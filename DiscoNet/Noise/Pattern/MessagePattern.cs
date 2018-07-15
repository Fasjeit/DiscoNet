﻿namespace DiscoNet.Noise.Pattern
{
    using System.Collections;
    using System.Collections.Generic;

    using DiscoNet.Noise.Enums;

    public class MessagePattern : IEnumerable<Tokens>
    {
        public List<Tokens> Tokens { get; set; } = new List<Tokens>();

        public IEnumerator<Tokens> GetEnumerator()
        {
            return this.Tokens.GetEnumerator();
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
}
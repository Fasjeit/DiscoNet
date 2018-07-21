namespace DiscoNet.Noise
{
    using System;

    using StrobeNet;
    using StrobeNet.Enums;

    /// <summary>
    /// Strobe hash object
    /// </summary>
    public class Hash : ICloneable
    {
        private readonly int outputLen;

        private bool streaming;

        private Strobe strobeState;

        /// <summary>
        /// Output (exrac) data from strobe state
        /// </summary>
        /// <param name="outputLength"></param>
        public Hash(int outputLength)
        {
            if (outputLength < 32)
            {
                throw new Exception(
                    "disco: an output length smaller than 256-bit (32 bytes) has security consequences");
            }

            this.strobeState = new Strobe("DiscoHash", 128);
            this.outputLen = outputLength;
        }

        /// <summary>
        /// Get copy of the DiscoHash in its current state.
        /// </summary>
        /// <returns></returns>
        public object Clone()
        {
            var cloned = (Strobe)this.strobeState.Clone();
            return new Hash(this.outputLen) { strobeState = cloned };
        }

        /// <summary>
        /// Write absorbs more data into the hash's state.
        /// </summary>
        /// <param name="inputData">Data to write</param>
        public int Write(byte[] inputData)
        {
            this.strobeState.Operate(false, Operation.Ad, inputData, 0, this.streaming);
            this.streaming = true;
            return inputData.Length;
        }

        /// <summary>
        /// Reads more output from the hash; reading affects the hash's state
        /// </summary>
        /// <returns></returns>
        public byte[] Sum()
        {
            var reader = (Strobe)this.strobeState.Clone();
            return reader.Operate(false, Operation.Prf, null, this.outputLen, false);
        }
    }
}
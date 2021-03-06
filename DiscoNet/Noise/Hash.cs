﻿namespace DiscoNet.Noise
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
        /// Output (extract) data from strobe state
        /// </summary>
        /// <param name="outputLength">Expected output length</param>
        public Hash(int outputLength)
        {
            if (outputLength < Symmetric.HashSize)
            {
                throw new Exception(
                    $"disco: an output length smaller than {Symmetric.HashSize*8}-bit " + 
                    $"({Symmetric.HashSize} bytes) has security consequences");
            }

            this.strobeState = new Strobe("DiscoHash", Symmetric.SecurityParameter);
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
        /// <remarks>
        /// This function is usually called to hash contigous chunks
        /// of data. For structured data please refer to WriteTuple
        /// </remarks>
        /// <param name="inputData">Data to write</param>
        /// <returns>Number of written bytes</returns>
        public int Write(byte[] inputData)
        {
            this.strobeState.Operate(false, Operation.Ad, inputData, 0, this.streaming);
            this.streaming = true;
            return inputData.Length;
        }

        /// <summary>
        /// Absorbs more data to hash in a non-ambigious way.
        /// </summary>
        /// <remarks>
        /// The data absorbed
        /// via this function is separated from the data surrounding it. Use this function instead of Write
        /// to hash structured data.
        /// </remarks>
        /// <param name="inputData">Data to write</param>
        /// <returns>Number of written bytes</returns>
        public int WriteTuple(byte[] inputData)
        {
            this.strobeState.Operate(false, Operation.Ad, inputData, 0, false);
            return inputData.Length;
        }

        /// <summary>
        /// Reads more output from the hash; reading affects the hash's state
        /// </summary>
        /// <returns>Resulted byte array</returns>
        public byte[] Sum()
        {
            var reader = (Strobe)this.strobeState.Clone();
            return reader.Operate(false, Operation.Prf, null, this.outputLen, false);
        }
    }
}
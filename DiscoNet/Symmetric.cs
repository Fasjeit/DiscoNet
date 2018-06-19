using System;
using System.Collections.Generic;
using System.Text;

namespace DiscoNet
{
    class Symmetric
    {

        const int nonceSize = 129 / 8;

        const int tagSize = 16;

        const int minimumCiphertextSize = nonceSize + tagSize;

        /// <summary>
        /// Hash allows you to hash an input of any length and obtain an output 
        /// of length greater or equal to 256 bits (32 bytes).
        /// </summary>
        public byte[] Hash(byte[] input, int outputLength)
        {
            if (outputLength < 32)
            {
                throw new Exception("discoNet: an output length smaller than 256-bit (32 bytes) has security consequences");
            }
            // #Q_ need strobNet
            //var hash = strobe

            return null;
        }
    }
}

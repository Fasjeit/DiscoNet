namespace DiscoNet.Noise.Enums
{
    /// <summary>
    /// Types of Noise handhske patterns
    /// </summary>
    public enum NoiseHandshakeType
    {
        /// <summary>
        /// Unknown token
        /// </summary>
        Unknown,

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
        /// </summary>
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

        NoiseIN
    }
}

namespace DiscoNet.Noise
{
    internal class HandshakeState
    {
        /// <summary>
        /// SymmetricState object
        /// </summary>
        public SymmetricState SymmetricState { get; set; }

        /// <summary>
        /// The local static key pair
        /// </summary>
        public KeyPair S { get; set; }

        /// <summary>
        /// The local ephemeral key pair
        /// </summary>
        public KeyPair E { get; set; }

        /// <summary>
        /// The remote party's static public key
        /// </summary>
        public KeyPair Rs { get; set; }

        /// <summary>
        /// The remote party's ephemeral public key
        /// </summary>
        public KeyPair Re { get; set; }

        /// <summary>
        /// Indicating the initiator or responder role.
        /// </summary>
        public bool Initiator { get; set; }

        /// <summary>
        /// A sequence of message pattern. Each message pattern is a sequence
        /// of tokens from the set ("e", "s", "ee", "es", "se", "ss")
        /// </summary>
        public MessagePattern[] MessagePatterns { get; set; }

        /// <summary>
        /// indicating if the role of the peer is to WriteMessage
        /// or ReadMessage
        /// </summary>
        public bool ShouldWrite { get; set; }

        /// <summary>
        /// Pre-shared key
        /// </summary>
        public byte[] Psk { get; set; }

        /// <summary>
        /// For test vectors
        /// </summary>
        public KeyPair DebugEphemeral { get; set; }
    }
}

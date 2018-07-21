namespace DiscoNet
{
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    /// <summary>
    /// Disco configuration
    /// </summary>
    public class Config
    {
        /// <summary>
        /// If the chosen handshake pattern requires the remote peer to send an unknown
        /// static public key as part of the handshake, this callback is mandatory in
        /// order to validate it
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="proof"></param>
        /// <returns></returns>
        public delegate bool PublicKeyVerifierDeligate(byte[] publicKey, byte[] proof);

        // The following constants represent the details of this implementation of the Noise specification.

        /// <summary>
        /// Implemented draft version
        /// </summary>
        public const string DiscoDraftVersion = "3";

        /// <summary>
        /// Implemented DH funtion
        /// </summary>
        public const string NoiseDH = "25519";

        // The following constants are taken directly from the Noise specification.

        /// <summary>
        /// Max max message len
        /// </summary>
        public const int NoiseMessageLength = 65535 - 2; // 2-byte length

        /// <summary>
        /// Noise max tag len
        /// </summary>
        private const int NoiseTagLength = Symmetric.TagSize;

        /// <summary>
        /// Noise max plaintext size
        /// </summary>
        public const int NoiseMaxPlaintextSize = Config.NoiseMessageLength - Config.NoiseTagLength;

        /// <summary>
        /// The peers to write and read in turns. 
        /// By default a noise protocol is full-duplex, meaning that both the client
        /// and the server can write on the channel at the same time. If this requirement
        /// is not respected by the application, the consequences could be catastrophic
        /// </summary>
        public bool HalfDuplex;

        /// <summary>
        /// The current peer's keyPair
        /// </summary>
        public KeyPair KeyPair;

        /// <summary>
        /// A pre-shared key for handshake patterns including a `psk` token
        /// </summary>
        public byte[] PreSharedKey;

        /// <summary>
        /// Any messages that the client and the server previously exchanged in clear
        /// </summary>
        public byte[] Prologue = { };

        /// <summary>
        /// The other peer's public key
        /// </summary>
        public byte[] RemoteKey;

        /// <summary>
        /// If the chosen handshake pattern requires the current peer to send a static
        /// public key as part of the handshake, this proof over the key is mandatory
        /// in order for the other peer to verify the current peer's key
        /// </summary>
        public byte[] StaticPublicKeyProof;

        /// <summary>
        /// The type of Noise protocol that the client and the server will go through
        /// </summary>
        public NoiseHandshakeType HandshakePattern { get; set; }

        /// <summary>
        /// Public key verifier Delegate method 
        /// </summary>
        public PublicKeyVerifierDeligate PublicKeyVerifier { get; set; }
    }
}
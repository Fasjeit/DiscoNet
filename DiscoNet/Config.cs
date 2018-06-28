namespace DiscoNet
{
    using System;

    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;

    public class Config
    {
        // The following constants represent the details of this implementation of the Noise specification.

        /// <summary>
        /// Implemented draft version
        /// </summary>
        const string DiscoDraftVersion = "3";

        /// <summary>
        /// Implemented DH funtion
        /// </summary>
        const string NoiseDH = "25519";

        // The following constants are taken directly from the Noise specification.

        /// <summary>
        /// Max max message len
        /// </summary>
        const int NoiseMessageLength = 65535 - 2; // 2-byte length

        /// <summary>
        /// Noise max tag len
        /// </summary>
        const int NoiseTagLength = 16;

        /// <summary>
        /// Noise max plaintext size
        /// </summary>
        const int NoiseMaxPlaintextSize = NoiseMessageLength - NoiseTagLength;

        /// <summary>
        /// the type of Noise protocol that the client and the server will go through
        /// </summary>
        public NoiseHandshakeType HandshakePattern { get; set; }

        /// <summary>
        /// The current peer's keyPair
        /// </summary>
        public KeyPair KeyPair;

        /// <summary>
        /// The other peer's public key
        /// </summary>
        public byte[] RemoteKey;

        /// <summary>
        /// Any messages that the client and the server previously exchanged in clear
        /// </summary>
        public byte[] Prologue;

        /// <summary>
        /// If the chosen handshake pattern requires the current peer to send a static
        /// public key as part of the handshake, this proof over the key is mandatory
        /// in order for the other peer to verify the current peer's key
        /// </summary>
        public byte[] StaticPublicKeyProof;


        /// <summary>
        /// If the chosen handshake pattern requires the remote peer to send an unknown
        /// static public key as part of the handshake, this callback is mandatory in
        /// order to validate it
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="proof"></param>
        /// <returns></returns>
        public delegate bool PublicKeyVerifierDeligate(object publicKey, byte[] proof);

        public PublicKeyVerifierDeligate PublicKeyVerifier;

        /// <summary>
        /// A pre-shared key for handshake patterns including a `psk` token
        /// </summary>
        public  byte[] PreSharedKey;

        /// <summary>
        /// By default a noise protocol is full-duplex, meaning that both the client
        /// and the server can write on the channel at the same time. Setting this value
        /// to true will require the peers to write and read in turns. If this requirement
        /// is not respected by the application, the consequences could be catastrophic
        /// </summary>
        public bool HalfDuplex;
    };
}


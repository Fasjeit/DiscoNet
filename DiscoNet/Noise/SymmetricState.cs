namespace DiscoNet.Noise
{
    using System;
    using System.Linq;
    using System.Text;

    using StrobeNet;

    /// <summary>
    /// Noise symmetric state
    /// </summary>
    public class SymmetricState
    {
        /// <summary>
        /// Current strobe state
        /// </summary>
        private readonly Strobe strobeState;

        /// <summary>
        /// Is state keyed
        /// </summary>
        public bool IsKeyed { get; private set; }

        internal SymmetricState(string protocolName)
        {
            this.strobeState = new Strobe(protocolName, Symmetric.SecurityParameter);
        }

        internal void MixKey(byte[] inputKeyMaterial)
        {
            this.strobeState.Ad(false, inputKeyMaterial);
            this.IsKeyed = true;
        }

        internal void MixHash(byte[] data)
        {
            this.strobeState.Ad(false, data);
        }

        internal void MixKeyAndHash(byte[] inputKeyMaterial)
        {
            this.strobeState.Ad(false, inputKeyMaterial);
        }

        internal byte[] GetHandshakeHash()
        {
            return this.strobeState.Prf(Symmetric.HashSize);
        }

        /// <summary>
        /// Encrypt the plaintext and authenticates the hash.
        /// Then insert the ciphertext in the running hash
        /// </summary>
        /// <param name="plaintext"></param>
        /// <returns></returns>
        internal byte[] EncryptAndHash(byte[] plaintext)
        {
            if (!this.IsKeyed)
            {
                // no keys, so we don't encrypt
                return plaintext;
            }

            var ciphertext = this.strobeState.SendEncUnauthenticated(false, plaintext);
            ciphertext = ciphertext.Concat(this.strobeState.SendMac(false, Symmetric.TagSize)).ToArray();
            return ciphertext;
        }

        internal byte[] DecryptAndHash(byte[] cipherText)
        {
            if (!this.IsKeyed)
            {
                // no keys, so nothing to decrypt
                return cipherText;
            }

            if (cipherText.Length < Symmetric.TagSize)
            {
                throw new Exception($"disco: the received payload is shorter then {Symmetric.TagSize} bytes");
            }

            var plaintextLength = cipherText.Length - Symmetric.TagSize;
            var plaintext = this.strobeState.RecvEncUnauthenticated(false, cipherText.Take(plaintextLength).ToArray());
            var verificationResult = this.strobeState.RecvMac(false, cipherText.Skip(plaintextLength).ToArray());

            if (!verificationResult)
            {
                throw new Exception("disco: cannot decrypt the payload");
            }

            return plaintext;
        }

        internal (Strobe initiatorState, Strobe responderState) Split()
        {
            var initiatorState = (Strobe)this.strobeState.Clone();
            initiatorState.Ad(true, Encoding.ASCII.GetBytes("initiator"));
            initiatorState.Ratchet(Symmetric.HashSize);

            var responderState = this.strobeState;
            responderState.Ad(true, Encoding.ASCII.GetBytes("responder"));
            responderState.Ratchet(Symmetric.HashSize);

            return (initiatorState, responderState);
        }
    }
}
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
        /// Cuuretn strobe state
        /// </summary>
        private readonly Strobe strobeState;

        /// <summary>
        /// Is state keyed
        /// </summary>
        public bool IsKeyed { get; private set; }

        internal SymmetricState(string protocolName)
        {
            this.strobeState = new Strobe(protocolName, 128);
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
            return this.strobeState.Prf(32);
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
            ciphertext = ciphertext.Concat(this.strobeState.SendMac(false, 16)).ToArray();
            return ciphertext;
        }

        internal byte[] DecryptAndHash(byte[] cipherText)
        {
            if (!this.IsKeyed)
            {
                // no keys, so nothing to decrypt
                return cipherText;
            }

            if (cipherText.Length < 16)
            {
                throw new Exception("disco: the received payload is shorter 16 bytes");
            }

            var plaintextLength = cipherText.Length - 16;
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
            initiatorState.Ratchet(32);

            var responderState = this.strobeState;
            responderState.Ad(true, Encoding.ASCII.GetBytes("responder"));
            responderState.Ratchet(32);

            return (initiatorState, responderState);
        }
    }
}
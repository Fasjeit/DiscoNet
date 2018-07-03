namespace DiscoNet.Noise
{
    using System;
    using System.Linq;
    using System.Text;

    using StrobeNet;

    public class SymmetricState
    {
        private readonly Strobe strobeState;

        public bool IsKeyed { get; private set; }

        public SymmetricState(string protocolName)
        {
            this.strobeState = new Strobe(protocolName, 128);
        }

        public void MixKey(byte[] inputKeyMaterial)
        {
            this.strobeState.Ad(false, inputKeyMaterial);
            this.IsKeyed = true;
        }

        public void MixHash(byte[] data)
        {
            this.strobeState.Ad(false, data);
        }

        public void MixKeyAndHash(byte[] inputKeyMaterial)
        {
            this.strobeState.Ad(false, inputKeyMaterial);
        }

        public byte[] GetHandshakeHash()
        {
            return this.strobeState.Prf(32);
        }

        /// <summary>
        /// Encrypt the plaintext and authenticates the hash.
        /// Then insert the ciphertext in the running hash
        /// </summary>
        /// <param name="plaintext"></param>
        /// <returns></returns>
        public byte[] EncryptAndHash(byte[] plaintext)
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

        public byte[] DecryptAndHash(byte[] cipherText)
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

        public (Strobe initiatorState, Strobe responderState) Split()
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

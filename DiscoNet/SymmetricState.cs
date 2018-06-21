using System;
using System.Collections.Generic;
using System.Text;

namespace DiscoNet
{
    using StrobeNet;
    using System.Linq;

    public class SymmetricState
    {
        private Strobe strobeState;

        private bool isKeyed;

        public SymmetricState(string protocolName)
        {
            this.strobeState = new Strobe(protocolName, 128);
        }

        public void MixKey(byte[] inputKeyMaterial)
        {
            this.strobeState.Ad(false, inputKeyMaterial);
            this.isKeyed = true;
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
            if (!this.isKeyed)
            {
                // no keys, so we don't encrypt
                return plaintext;
            }

            var ciphertext = this.strobeState.SendEncUnauthenticated(false, plaintext);
            ciphertext = ciphertext.Concat(strobeState.SendMac(false, 16)).ToArray();
            return ciphertext;
        }

        public byte[] DecryptAndHash(byte[] cipherText)
        {
            if (!this.isKeyed)
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
    }
}

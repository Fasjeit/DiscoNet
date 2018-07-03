using System;
using System.Collections.Generic;
using System.Text;

namespace DiscoNet
{
    using DiscoNet.Noise;
    using DiscoNet.Noise.Enums;
    using DiscoNet.Noise.Pattern;

    using StrobeNet;

    class DiscoOoooo
    {

        // This allows you to initialize a peer.
        // * see `patterns` for a list of available handshakePatterns
        // * initiator = false means the instance is for a responder
        // * prologue is a byte string record of anything that happened prior the Noise handshakeState
        // * s, e, rs, re are the local and remote static/ephemeral key pairs to be set (if they exist)
        // the function returns a handshakeState object.
        public static HandshakeState Initialize(
            NoiseHandshakeType handshakeType,
            bool initiator,
            byte[] prologue,
            KeyPair s,
            KeyPair e,
            KeyPair rs,
            KeyPair re)
        {
            var handshakePattern = HandshakePattern.GetPattern(handshakeType);

            var handshakeState = new HandshakeState
            {
                SymmetricState = new SymmetricState($"Noise_{handshakePattern.Name}_25519_STROBEv1.0.2"),
                Initiator = initiator, 
                ShouldWrite = initiator,
            };
            handshakeState.SymmetricState.MixHash(prologue);

            if (s != null)
            {
                handshakeState.S = s;
            }

            if (e != null)
            {
                throw new NotSupportedException("disco: fallback patterns are not implemented");
            }

            if (rs != null)
            {
                handshakeState.Rs = rs;
            }

            if (re != null)
            {
                throw new NotSupportedException("disco: fallback patterns are not implemented");
            }

            //Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern,
            //with the specified public key as input (see Section 7 for an explanation of pre-messages).
            //If both initiator and responder have pre-messages, the initiator's public keys are hashed first.

            // initiator pre-message pattern
            foreach (var token in handshakePattern.PreMessagePatterns[0])
            {
                if (token == Tokens.TokenS)
                {
                    if (initiator)
                    {
                        if (s == null)
                        {
                            throw new Exception("disco: the static key of the client should be set");
                        }

                        handshakeState.SymmetricState.MixHash(s.PublicKey);
                    }
                    else
                    {
                        if (rs == null)
                        {
                            throw new Exception("disco: the remote static key of the server should be set");
                        }

                        handshakeState.SymmetricState.MixHash(rs.PublicKey);
                    }
                }
                else
                {
                    throw new Exception("disco: token of pre-message not supported");
                }
            }

            // responder pre-message pattern
            foreach (var token in handshakePattern.PreMessagePatterns[1])
            {
                if (token == Tokens.TokenS)
                {
                    if (initiator)
                    {
                        if (rs == null)
                        {
                            throw new Exception("disco: the remote static key of the client should be set");
                        }

                        handshakeState.SymmetricState.MixHash(rs.PublicKey);
                    }
                    else
                    {
                        if (s == null)
                        {
                            throw new Exception("disco: the static key of the server should be set");
                        }

                        handshakeState.SymmetricState.MixHash(s.PublicKey);
                    }
                }
                else
                {
                    throw new NotSupportedException("disco: token of pre - message not supported");
                }
            }

            handshakeState.MessagePatterns = handshakePattern.MessagePatterns;
            return handshakeState;
        }
    }
}

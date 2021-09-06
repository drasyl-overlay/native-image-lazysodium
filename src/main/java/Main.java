import com.goterl.lazysodium.interfaces.AEAD;
import com.goterl.lazysodium.utils.KeyPair;
import com.goterl.lazysodium.utils.SessionPair;
import com.sun.jna.Native;

public class Main {
    public static void main(final String[] args) throws Exception {
        System.out.println("JNA Version: " + Native.VERSION);

        while (true) {
            final byte[] nonce = Crypto.randomBytes(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES);
            final byte[] authTag = Crypto.randomBytes(1);
            final String msg = "Hello World!";

            final KeyPair keyPair = Crypto.INSTANCE.generateLongTimeKeyPair();
            final KeyPair keyPair2 = Crypto.INSTANCE.generateLongTimeKeyPair();
            final KeyPair ag = Crypto.INSTANCE.convertLongTimeKeyPairToKeyAgreementKeyPair(keyPair);
            final KeyPair ag2 = Crypto.INSTANCE.convertLongTimeKeyPairToKeyAgreementKeyPair(keyPair2);

            // generate session pair
            final SessionPair sessionPair1 = Crypto.INSTANCE.generateSessionKeyPair(ag, ag2.getPublicKey());
            final SessionPair sessionPair2 = Crypto.INSTANCE.generateSessionKeyPair(ag2, Crypto.INSTANCE.convertIdentityKeyToKeyAgreementKey(keyPair.getPublicKey()));

            // encrypt
            final byte[] enc = Crypto.INSTANCE.encrypt(msg.getBytes(), authTag, nonce, sessionPair1);

            // decrypt
            Crypto.INSTANCE.decrypt(enc, authTag, nonce, sessionPair2);

            final KeyPair ep = Crypto.INSTANCE.generateEphemeralKeyPair();
            final KeyPair ep2 = Crypto.INSTANCE.generateEphemeralKeyPair();

            // generate session pair
            final SessionPair sessionPair3 = Crypto.INSTANCE.generateSessionKeyPair(ep, ep2.getPublicKey());
            final SessionPair sessionPair4 = Crypto.INSTANCE.generateSessionKeyPair(ep2, ep.getPublicKey());

            // encrypt
            final byte[] enc2 = Crypto.INSTANCE.encrypt(msg.getBytes(), authTag, nonce, sessionPair3);

            // decrypt
            Crypto.INSTANCE.decrypt(enc2, authTag, nonce, sessionPair4);

            // Sign
            final byte[] sig = Crypto.INSTANCE.sign(msg.getBytes(), keyPair.getSecretKey());

            // verify
            Crypto.INSTANCE.verifySignature(sig, msg.getBytes(), keyPair.getPublicKey());
        }
    }
}

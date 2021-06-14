import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.Sodium;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.utils.LibraryLoader;
import com.sun.jna.Native;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        System.out.println("JNA Version: " + Native.VERSION);

//        Native.register(Sodium.class, "sodium");
//        Native.register(SodiumJava.class, "sodium");
//
//        final byte[] publicKey = new byte[32];
//        final byte[] secretKey = new byte[64];
//        new SodiumJava().crypto_sign_keypair(publicKey, secretKey);

        final LazySodiumJava sodium = new LazySodiumJava(new SodiumJava());

        final byte[] publicKey = new byte[32];
        final byte[] secretKey = new byte[64];
        sodium.cryptoSignKeypair(publicKey, secretKey);

        System.out.println(Arrays.toString(publicKey));
        System.out.println(Arrays.toString(secretKey));
//
//        System.out.println(Arrays.toString(publicKey));
//        System.out.println(Arrays.toString(secretKey));
    }
}

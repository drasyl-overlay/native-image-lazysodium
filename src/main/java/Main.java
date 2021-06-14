import com.goterl.lazysodium.Sodium;
import com.goterl.lazysodium.SodiumJava;
import com.sun.jna.Native;

public class Main {
    public static void main(String[] args) {
        System.out.println("JNA Version: " + Native.VERSION);

        Native.register(Sodium.class, "sodium");
        Native.register(SodiumJava.class, "sodium");
    }
}

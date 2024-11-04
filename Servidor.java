import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Servidor {
    private static final int PUERTO = 12345;
    private static final String ALGORITMO_CIFRADO = "AES/CBC/PKCS5Padding";
    private static final String ALGORITMO_FIRMA = "SHA1withRSA";
    
    private static PublicKey K_w_plus;
    private static PrivateKey K_w_minus;

    public static void main(String[] args) {
        try {
            cargarLlaves();
            ServerSocket serverSocket = new ServerSocket(PUERTO);
            System.out.println("Servidor escuchando en el puerto " + PUERTO);
            cargarLlaves();
            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("Cliente conectado a nuevo hilo.");
                
                // Crear un nuevo hilo para manejar al cliente
                Thread clientThread = new Thread(new ClientHandler(socket, K_w_minus));
                clientThread.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    
    private static void cargarLlaves() throws Exception {
        // Cargar las llaves pública y privada desde los archivos
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        try (FileInputStream fis = new FileInputStream("Clientes/public.key")) {
            byte[] keyBytes = fis.readAllBytes();
            K_w_plus = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        }
        try (FileInputStream fis = new FileInputStream("private.key")) {
            byte[] keyBytes = fis.readAllBytes();
            K_w_minus = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
    }

}

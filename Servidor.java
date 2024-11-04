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
            while (true) {
                try (Socket socket = serverSocket.accept();
                     ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                     ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
                     
                    // 1. Leer mensaje inicial
                    String mensajeInicial = (String) in.readObject(); // Cambia esto para que coincida con el tipo de objeto
                    System.out.println("Mensaje inicial recibido: " + mensajeInicial);

                    // 2. Leer reto cifrado
                    byte[] retoCifrado = (byte[]) in.readObject();
                    // 3. Desencriptar reto
                    byte[] Rta = descifrarReto(retoCifrado);
                    System.out.println("Rta calculada: " + Arrays.toString(Rta));

                    // 4. Enviar respuesta al cliente
                    System.out.println("Enviando respuesta al cliente: " + Arrays.toString(Rta));
                    out.write(Rta);
                    out.flush();

                    // 6. Leer respuesta del cliente
                    String respuestaCliente = (String) in.readObject();
                    if ("OK".equals(respuestaCliente)) {
                        // 7. Generar G, P, G^x
                        BigInteger G = new BigInteger("2"); // Base
                        BigInteger P = new BigInteger("23"); // Primos
                        BigInteger x = BigInteger.valueOf(new SecureRandom().nextInt(22) + 1); // Secreto

                        // Calcular G^x
                        BigInteger Gx = G.pow(x.intValue());
                        
                        // 8. Enviar G, P, G^x al cliente
                        out.writeObject(G);
                        out.writeObject(P);
                        out.writeObject(Gx);
                        byte[] firma = firmarTupla(G, P, Gx);
                        out.writeObject(firma);
                        out.flush();
                        
                        // 8. Generar y para el cliente
                        // Aquí podrías generar un valor y si estás implementando alguna lógica
                    } else {
                        System.out.println("Cliente respondió ERROR");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] firmarTupla(BigInteger G, BigInteger P, BigInteger Gx) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(K_w_minus);
            // Crear la representación de la tupla
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(G);
            objectOutputStream.writeObject(P);
            objectOutputStream.writeObject(Gx);
            objectOutputStream.flush();
            byte[] tuplaBytes = byteArrayOutputStream.toByteArray();

            // Firmar la tupla
            signature.update(tuplaBytes);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
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

    private static byte[] descifrarReto(byte[] retoCifrado) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, K_w_minus);
        return cipher.doFinal(retoCifrado);
    }
}

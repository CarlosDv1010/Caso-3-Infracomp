package Clientes;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;

public class Cliente implements Runnable {
    public static BigInteger G;
    public static BigInteger P;
    public BigInteger Gx;
    private static PublicKey K_w_plus;
    private int uid;

    public Cliente(int uid) {
        this.uid = uid;
    }

    public static void main(String[] args) throws Exception {
        // Cargar las llaves antes de iniciar los clientes
        cargarLlaves();

        // Crear múltiples hilos de cliente
        int numeroClientes = 5; // Cambia este número para ajustar la cantidad de clientes concurrentes
        for (int i = 1; i <= numeroClientes; i++) {
            new Thread(new Cliente(i)).start();
        }
    }



    @Override
    public void run() {
        try (Socket socket = new Socket("localhost", 12345);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            
            // Aquí comienza la lógica del cliente
            out.writeObject("SECINIT Cliente " + uid);
            out.flush();
            System.out.println("(Cliente " + uid + "): " + "Mensaje inicial enviado.");

            // Generar y enviar el reto cifrado
            byte[] reto = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(reto);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, K_w_plus);
            byte[] R = cipher.doFinal(reto);

            out.writeObject(R);
            out.flush();
            System.out.println("(Cliente " + uid + "): " + "Reto cifrado enviado.");

            // Verificar la respuesta
            byte[] RtaRecibido = new byte[reto.length];
            in.read(RtaRecibido);
            System.out.println("(Cliente " + uid + "): " + "Rta recibida del servidor: " + Arrays.toString(RtaRecibido));

            if (MessageDigest.isEqual(RtaRecibido, reto)) {
                System.out.println("(Cliente " + uid + "): " + "Rta verificada correctamente.");
                out.writeObject("OK");
                out.flush();
            } else {
                System.out.println("(Cliente " + uid + "): " + "Rta no válida.");
                out.writeObject("ERROR");
                out.flush();
            }

            // Recibir y verificar los valores G, P y Gx
            G = (BigInteger) in.readObject();
            System.out.println("(Cliente " + uid + "): " + "G recibido: " + G);
            P = (BigInteger) in.readObject();
            System.out.println("(Cliente " + uid + "): " + "P recibido: " + P);
            Gx = (BigInteger) in.readObject();
            System.out.println("(Cliente " + uid + "): " + "G^x recibido: " + Gx);
            byte[] firma = (byte[]) in.readObject();
            random = new SecureRandom();
            BigInteger y;
            do {
                y = new BigInteger(P.bitLength(), random);
            } while (y.compareTo(P) >= 0 || y.compareTo(BigInteger.ONE) < 0);

            
            System.out.println("(Cliente " + uid + "): " + "Firma recibida: " + Arrays.toString(firma));
            boolean firmaValida = verificarFirma(G, P, Gx, firma);
            if (firmaValida) {
                System.out.println("(Cliente " + uid + "): " + "Firma válida. Continuando...");
                out.writeObject("OK");
            } else {
                System.out.println("(Cliente " + uid + "): " + "Firma inválida.");
                out.writeObject("NO");
                throw new Exception("Firma inválida.");
            }

            BigInteger Gy = G.modPow(y, P);
            out.writeObject(G);
            out.writeObject(P);
            out.writeObject(Gy);
            out.flush();

            BigInteger Gxy = Gx.modPow(y, P);
            byte[] gxyBytes = Gxy.toByteArray();

            if (gxyBytes.length < (256 / 8 + 384 / 8)) {
                throw new IllegalArgumentException("El valor Gxy no tiene suficientes bytes para generar las llaves.");
            }

            byte[] aesKeyBytes = Arrays.copyOfRange(gxyBytes, 0, 32);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            byte[] hmacKeyBytes = Arrays.copyOfRange(gxyBytes, 32, 32 + 48);
            SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");

            byte[] iv = (byte[]) in.readObject();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean verificarFirma(BigInteger G, BigInteger P, BigInteger Gx, byte[] firma) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(K_w_plus);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(G);
            objectOutputStream.writeObject(P);
            objectOutputStream.writeObject(Gx);
            objectOutputStream.flush();
            byte[] tuplaBytes = byteArrayOutputStream.toByteArray();

            signature.update(tuplaBytes);
            return signature.verify(firma);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static void cargarLlaves() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        try (FileInputStream fis = new FileInputStream("Clientes/public.key")) {
            byte[] keyBytes = fis.readAllBytes();
            K_w_plus = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        }
    }
}

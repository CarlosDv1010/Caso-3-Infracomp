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

public class Cliente {
    public static BigInteger G;
    public static BigInteger P;
    public static BigInteger Gx;
    private static PublicKey K_w_plus;
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("localhost", 12345);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {             
                cargarLlaves();
                
                // 1 Cliente manda "SECINIT"
                out.writeObject("SECINIT");
                out.flush();
                System.out.println("Mensaje inicial enviado.");

                // 2a Cliente Calcula R=C(K_w+, Reto)
                byte[] reto = new byte[16]; // Cambia esto según tu implementación
                SecureRandom random = new SecureRandom();
                random.nextBytes(reto);

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, K_w_plus);
                byte[] R = cipher.doFinal(reto);

                // 2b Cliente envia R al servidor
                out.writeObject(R);
                out.flush();
                System.out.println("Reto cifrado enviado.");

                // 5 Cliente verifica Rta
                byte[] RtaRecibido = new byte[reto.length];
                in.read(RtaRecibido);
                System.out.println("Rta recibida del servidor: " + Arrays.toString(RtaRecibido));
                // 5 Cliente verifica Rta==Reto
                if (MessageDigest.isEqual(RtaRecibido, reto)) {
                    System.out.println("Rta verificada correctamente.");
                    out.writeObject("OK");
                    out.flush();
                } else {
                    System.out.println("Rta no válida.");
                    out.writeObject("ERROR");
                    out.flush();
                }
                

                // 9 Cliente verifica F(K_w-,(G,P,G^x))
                // Aquí debes implementar la verificación según tu lógica específica
                // Recibir G, P y G^x
                G = (BigInteger) in.readObject();
                P = (BigInteger) in.readObject();
                Gx = (BigInteger) in.readObject();
                random = new SecureRandom();
                BigInteger y;
                do {
                    y = new BigInteger(P.bitLength(), random); // Generar un BigInteger aleatorio en el rango de 0 a P-1
                } while (y.compareTo(P) >= 0 || y.compareTo(BigInteger.ONE) < 0); // Asegurarse de que 0 < y < P
                byte[] firma = (byte[]) in.readObject();

                boolean firmaValida = verificarFirma(G, P, Gx, firma);
                if (firmaValida) {
                    System.out.println("Firma válida. Continuando...");
                    // Continúa con el flujo del programa...
                    out.writeObject("OK"); // Enviar OK al servidor
                } else {
                    System.out.println("Firma inválida.");
                    System.out.println("ERROR");
                    throw new Exception("Firma inválida.");
                }
                // Calcular G^y
                BigInteger Gy = G.modPow(y, P);

                out.writeObject(G);
                System.out.println("G enviado: " + G);
                out.writeObject(P);
                System.out.println("P enviado: " + P);
                out.writeObject(Gy);
                System.out.println("G^y enviado: " + Gy);
                out.flush();

                BigInteger Gxy = Gx.modPow(y, P);

                // Convertir Gxy en bytes
                byte[] gxyBytes = Gxy.toByteArray();

                // Verificar si hay suficientes bytes para las dos llaves
                if (gxyBytes.length < (256 / 8 + 384 / 8)) {
                    throw new IllegalArgumentException("El valor Gxy no tiene suficientes bytes para generar las llaves.");
                }

                // Derivar la llave AES (256 bits = 32 bytes)
                byte[] aesKeyBytes = Arrays.copyOfRange(gxyBytes, 0, 32);
                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                // Derivar la llave HMAC (384 bits = 48 bytes)
                byte[] hmacKeyBytes = Arrays.copyOfRange(gxyBytes, 32, 32 + 48);
                SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");

                

            }
        
            
    }

    private static boolean verificarFirma(BigInteger G, BigInteger P, BigInteger Gx, byte[] firma) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(K_w_plus);
            // Crear la representación de la tupla
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(G);
            objectOutputStream.writeObject(P);
            objectOutputStream.writeObject(Gx);
            objectOutputStream.flush();
            byte[] tuplaBytes = byteArrayOutputStream.toByteArray();

            // Verificar la firma
            signature.update(tuplaBytes);
            return signature.verify(firma);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    // Métodos para cifrado y HMAC
    public static byte[] cifrar(byte[] key, byte[] data) {
        return data;
        // Implementa el cifrado
    }

    public static byte[] calcularHMAC(byte[] key, byte[] data) {
        return data;
        // Implementa el cálculo de HMAC
    }
    private static void cargarLlaves() throws Exception {
        // Cargar las llaves pública y privada desde los archivos
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        try (FileInputStream fis = new FileInputStream("Clientes/public.key")) {
            byte[] keyBytes = fis.readAllBytes();
            K_w_plus = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        }
    }
    
}

package Clientes;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

public class Cliente {
    public static BigInteger G;
    public static BigInteger P;
    public static BigInteger Gx;
    private static PublicKey K_w_plus;
    public static void main(String[] args) {
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
            } else {
                System.out.println("Rta no válida.");
                out.writeObject("ERROR");
            }
            out.flush();

            // 9 Cliente verifica F(K_w-,(G,P,G^x))
            // Aquí debes implementar la verificación según tu lógica específica
            // Recibir G, P y G^x
            G = (BigInteger) in.readObject();
            P = (BigInteger) in.readObject();
            Gx = (BigInteger) in.readObject();
            BigInteger x = new BigInteger(128, random);
        
        // Asegurarse de que x esté en el rango [1, p-1]
        while (x.compareTo(P.subtract(BigInteger.ONE)) >= 0 || x.equals(BigInteger.ZERO)) {
            x = new BigInteger(128, random);
        }
            byte[] firma = (byte[]) in.readObject();
            boolean firmaValida = verificarFirma(G, P, Gx, firma);
            if (firmaValida) {
                System.out.println("Firma válida. Continuando...");
                // Continúa con el flujo del programa...
                out.writeObject("OK"); // Enviar OK al servidor
            } else {
                System.out.println("Firma inválida.");
                System.out.println("ERROR");
            }
            // 11 Cliente envía (G^x)^y al servidor
            BigInteger y = G.modPow(x, P);
            BigInteger Gxy = Gx.pow(y.intValue());
            BigInteger Gy = G.pow(y.intValue());
            out.writeObject(Gy);
            out.flush();
            //11.a Generar llave simetrica para cifrar K_AB1,Generar llave simetrica para MAC K_AB2
            // 13 Cliente envia C(K_AB1, uid) y HMAC(K_AB2, uid)
            // byte[] uid = "user123".getBytes(); // Ejemplo de uid
            // byte[] uidCifrado = cifrar(K_AB1, uid);
            // byte[] uidHMAC = calcularHMAC(K_AB2, uid);
            // out.write(uidCifrado);
            // out.write(uidHMAC);
            // out.flush();

            // 18 Cliente envia "TERMINAR" al servidor
            out.writeObject("TERMINAR");
            out.flush();

        } catch (Exception e) {
            e.printStackTrace();
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

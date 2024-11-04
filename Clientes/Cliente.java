package Clientes;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;

public class Cliente implements Runnable {
    public static BigInteger G;
    public static BigInteger P;
    public BigInteger Gx;
    private static PublicKey K_w_plus;
    private int uid;
    private int paqueteIdInicial;
    private int numConsultas;
    private static Map<Integer, String> estadosMap = new HashMap<>();

    public Cliente(int uid, int paqueteIdInicial, int numConsultas) {
        this.uid = uid;
        this.paqueteIdInicial = paqueteIdInicial;
        this.numConsultas = numConsultas;
    }

    public static void main(String[] args) throws Exception {

        estadosMap.put(-1, "NOEXISTE/INVALIDO");
        estadosMap.put(1, "ENOFICINA");
        estadosMap.put(2, "RECOGIDO");
        estadosMap.put(3, "ENCLASIFICACION");
        estadosMap.put(4, "DESPACHADO");
        estadosMap.put(5, "ENENTREGA");
        estadosMap.put(6, "ENTREGADO");
        estadosMap.put(7, "DESCONOCIDO");
        // Cargar las llaves antes de iniciar los clientes
        cargarLlaves();

        // Crear múltiples hilos de cliente
        int numeroClientes = 5; // Cambia este número para ajustar la cantidad de clientes concurrentes
        for (int i = 1; i <= numeroClientes; i++) {
            new Thread(new Cliente(i, i, 10)).start();
        }
    }



    @Override
    public void run() {
        
        
        try (Socket socket = new Socket("localhost", 12345);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject(numConsultas);
            out.flush();
            while (numConsultas > 0){
                int currentPaqueteId = paqueteIdInicial + numConsultas - 1;
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
                out.writeObject(Gy);
                System.out.println("(Cliente " + uid + "): " + "G^y enviado: " + Gy);
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

                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher2.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

                String id = String.format("%d", uid);
                byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);

                byte[] idCifrado = cipher2.doFinal(idBytes);

                Mac mac = Mac.getInstance("HmacSHA384");
                mac.init(hmacKey);

                byte[] hmac = mac.doFinal(idBytes);

                IvParameterSpec ivSpec2 = new IvParameterSpec(iv);
                Cipher cipher3 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher3.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec2);

                String idPaquete = String.format("%d", currentPaqueteId);
                byte[] idPaqueteBytes = idPaquete.getBytes(StandardCharsets.UTF_8);

                byte[] idPaqueteCifrado = cipher3.doFinal(idPaqueteBytes);

                Mac macPaquete = Mac.getInstance("HmacSHA384");
                macPaquete.init(hmacKey);

                byte[] hmacPaquete = macPaquete.doFinal(idPaqueteBytes);


                out.writeObject(idCifrado);
                System.out.println("(Cliente " + uid + "): " + "ID cifrado enviado: " + Arrays.toString(idCifrado));
                out.writeObject(hmac);
                System.out.println("(Cliente " + uid + "): " + "HMAC enviado: " + Arrays.toString(hmac));
                out.writeObject(idPaqueteCifrado);
                System.out.println("(Cliente " + uid + "): " + "ID Paquete cifrado enviado: " + Arrays.toString(idPaqueteCifrado));
                out.writeObject(hmacPaquete);
                System.out.println("(Cliente " + uid + "): " + "HMAC Paquete enviado: " + Arrays.toString(hmacPaquete));
                out.flush();

                // Recibir y verificar la respuesta
                byte[] idEstado = (byte[]) in.readObject();
                System.out.println("(Cliente " + uid + "): " + "Respuesta recibida: " + Arrays.toString(idEstado));
                byte[] hmacEstado = (byte[]) in.readObject();
                System.out.println("(Cliente " + uid + "): " + "HMAC recibido: " + Arrays.toString(hmacEstado));

                Cipher cipher4 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher4.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
                byte[] idEstadoDescifrado = cipher4.doFinal(idEstado);
                String idEstadoDescifradoString = new String(idEstadoDescifrado, StandardCharsets.UTF_8);

                mac.init(hmacKey);
                byte[] hmacCalculado = mac.doFinal(idEstadoDescifrado);
                if (!Arrays.equals(hmacEstado, hmacCalculado)) {
                    throw new SecurityException("La HMAC del ID del paquete no es válida.");
                }

                System.out.println("(Cliente " + uid + "): " + "ID Estado descifrado: " + estadosMap.get(Integer.parseInt(idEstadoDescifradoString)));
                out.writeObject("TERMINAR");
                numConsultas--;
                
            }


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

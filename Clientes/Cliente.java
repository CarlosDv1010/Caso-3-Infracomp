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
import java.util.Scanner;


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
        cargarLlaves();

        Scanner scanner = new Scanner(System.in);

        System.out.print("Introduce el número de clientes: ");
        int numeroClientes = scanner.nextInt();

        System.out.print("Introduce el número de consultas por cliente: ");
        int numConsultas = scanner.nextInt();

        for (int i = 1; i <= numeroClientes; i++) {
            new Thread(new Cliente(i, i, numConsultas)).start();
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
                out.writeObject("SECINIT Cliente " + uid);
                out.flush();
                System.out.println(uid + " SECINIT");

                byte[] reto = new byte[117];
                SecureRandom random = new SecureRandom();
                random.nextBytes(reto);

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, K_w_plus);
                byte[] R = cipher.doFinal(reto);

                out.writeObject(R);
                out.flush();

                byte[] RtaRecibido = new byte[reto.length];
                in.read(RtaRecibido);
                

                if (MessageDigest.isEqual(RtaRecibido, reto)) {
                    System.out.println(uid + " Reto cifrado es OK");
                    out.writeObject("OK");
                    out.flush();
                } else {
                    System.out.println(uid + " Reto cifrado es ERROR");
                    out.writeObject("ERROR");
                    out.flush();
                }

                // Recibir y verificar los valores G, P y Gx
                G = (BigInteger) in.readObject();
                P = (BigInteger) in.readObject();
                Gx = (BigInteger) in.readObject();
                byte[] firma = (byte[]) in.readObject();
                random = new SecureRandom();
                BigInteger y;
                do {
                    y = new BigInteger(P.bitLength(), random);
                } while (y.compareTo(P) >= 0 || y.compareTo(BigInteger.ONE) < 0);

                boolean firmaValida = verificarFirma(G, P, Gx, firma);
                if (firmaValida) {
                    System.out.println(uid+" Firma es OK");
                    out.writeObject("OK");
                } else {
                    System.out.println(uid + " Firma es ERROR");
                    out.writeObject("ERROR");
                    throw new Exception(" Firma inválida.");
                }

                BigInteger Gy = G.modPow(y, P);
                out.writeObject(Gy);
                out.flush();

                BigInteger Gxy = Gx.modPow(y, P);
                byte[] gxyBytes = Gxy.toByteArray();

                if (gxyBytes.length < (256 / 8 + 384 / 8)) {
                    throw new IllegalArgumentException("El valor Gxy no tiene suficientes bytes para generar las llaves.");
                }

                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                byte[] digest = sha512.digest(gxyBytes);

                byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, 32);
                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                byte[] hmacKeyBytes = Arrays.copyOfRange(digest, 32, 64);
                SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");

                byte[] iv = (byte[]) in.readObject();
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

                String id = String.format("%d", uid);
                byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
                byte[] idCifrado = cipher.doFinal(idBytes);

                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(hmacKey);
                byte[] hmac = mac.doFinal(idBytes);

                String idPaquete = String.format("%d", currentPaqueteId);
                byte[] idPaqueteBytes = idPaquete.getBytes(StandardCharsets.UTF_8);
                byte[] idPaqueteCifrado = cipher.doFinal(idPaqueteBytes);

                byte[] hmacPaquete = mac.doFinal(idPaqueteBytes);

                out.writeObject(idCifrado);
                out.writeObject(hmac);
                out.writeObject(idPaqueteCifrado);
                out.writeObject(hmacPaquete);
                out.flush();

                byte[] idEstado = (byte[]) in.readObject();
                byte[] hmacEstado = (byte[]) in.readObject();

                cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
                byte[] idEstadoDescifrado = cipher.doFinal(idEstado);
                String idEstadoDescifradoString = new String(idEstadoDescifrado, StandardCharsets.UTF_8);

                byte[] hmacCalculado = mac.doFinal(idEstadoDescifrado);
                if (!Arrays.equals(hmacEstado, hmacCalculado)) {
                    throw new SecurityException("La HMAC del ID del estado no es válida.");
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

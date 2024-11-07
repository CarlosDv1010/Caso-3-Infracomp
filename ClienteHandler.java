import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
class ClientHandler implements Runnable {
    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private static PrivateKey K_w_minus;
    private int sid;
    private static ArrayList<Paquete> tablaPaquetes;
    class StreamGobbler extends Thread {
        private InputStream inputStream;
        private StringBuilder output;
    
        public StreamGobbler(InputStream inputStream, StringBuilder output) {
            this.inputStream = inputStream;
            this.output = output;
        }
    
        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    public ClientHandler(Socket socket, PrivateKey K_w_minusR, int sid, ArrayList<Paquete> tablaPaquetesR) {
        tablaPaquetes = tablaPaquetesR;
        this.sid = sid;
        this.socket = socket;
        K_w_minus = K_w_minusR;
        try {
            this.in = new ObjectInputStream(socket.getInputStream());
            this.out = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        
        try {
            Integer numConsultas = (Integer) in.readObject();
            while (numConsultas > 0){

                String mensajeInicial = (String) in.readObject();
                byte[] retoCifrado = (byte[]) in.readObject();
                long startReto = System.currentTimeMillis();
                byte[] Rta = descifrarReto(retoCifrado);
                long endReto = System.currentTimeMillis();
                System.out.println("Tiempo para responder el reto: " + (endReto - startReto) + " ms");

                out.write(Rta);
                out.flush();

                String respuestaCliente = (String) in.readObject();
                
                if ("OK".equals(respuestaCliente)) {
                    long startGen = System.currentTimeMillis();
                    String opensslPath = "Openssl\\openssl";
                    Process process = Runtime.getRuntime().exec(opensslPath + " dhparam -text 1024");

                    StringBuilder output = new StringBuilder();
                    StringBuilder errorOutput = new StringBuilder();

                    StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream(), output);
                    StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), errorOutput);
                    outputGobbler.start();
                    errorGobbler.start();

                    process.waitFor();
                    outputGobbler.join();  
                    errorGobbler.join();   

                    String opensslOutput = output.toString();

                    Pattern primePattern = Pattern.compile("prime:.*?\\n?\\s*([0-9A-Fa-f:\\s]+)", Pattern.DOTALL);
                    Pattern generatorPattern = Pattern.compile("generator:.*?(\\d+)", Pattern.DOTALL);

                    Matcher primeMatcher = primePattern.matcher(opensslOutput);
                    Matcher generatorMatcher = generatorPattern.matcher(opensslOutput);

                    BigInteger P = null;
                    BigInteger G = null;

                    if (primeMatcher.find()) {
                        String primeHex = primeMatcher.group(1).replace(":", "").replace("\n", "").replace(" ", "").trim();
                        P = new BigInteger(primeHex, 16);
                    }

                    if (generatorMatcher.find()) {
                        String generatorStr = generatorMatcher.group(1).trim();
                        G = new BigInteger(generatorStr);
                    }


                    String string = "00:de:07:5c:4d:2c:2d:cb:da:0b:1c:8f:62:87:22:d7:e7:c2:9c:f6:e7:a6:b7:da:0b:57:4e:52:96:dd:d4:8f:7a:79:a5:9e:3c:8d:f4:ce:29:83:6c:75:60:ad:a2:19:5e:44:67:a3:1b:50:52:8e:bf:d0:66:bb:4f:ee:85:52:56:3b:61:16:12:82:6e:b5:1d:20:4f:7a:cc:f2:fd:3b:86:ef:7c:7d:00:b9:3d:73:e8:8f:58:0b:56:c2:41:c0:53:b4:19:ef:23:6f:c0:38:6e:f1:87:34:57:38:8e:f1:f4:a8:4d:21:ad:a3:16:7c:81:89:46:51:88:53:05:a0:cf";
                    String string2 = string.replace(":", "");

                    SecureRandom random = new SecureRandom();
                    BigInteger x;
                    
                    do {
                        x = new BigInteger(P.bitLength(), random); 
                    } while (x.compareTo(P) >= 0 || x.compareTo(BigInteger.ONE) < 0); 
                    
                    BigInteger Gx = G.modPow(x, P);

                    long endGen = System.currentTimeMillis();
                    System.out.println("Tiempo para generar G, P y G^x: " + (endGen - startGen) + " ms");
                    out.writeObject(G);
                    out.writeObject(P);
                    out.writeObject(Gx);
                    byte[] firma = firmarTupla(G, P, Gx);
                    out.writeObject(firma);
                    out.flush();
                    long startVerif = System.currentTimeMillis();
                    String respuestaCliente2 = (String) in.readObject();
                    if (!"OK".equals(respuestaCliente2)) {
                        throw new IllegalArgumentException("El cliente respondió con ERROR.");
                    }

                    BigInteger Gy = (BigInteger) in.readObject();
                    long startCifradoAsimetrico = System.currentTimeMillis();
                    BigInteger Gyx = Gy.modPow(x, P);

                    byte[] gxyBytes = Gyx.toByteArray();

                    MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                    byte[] digest = sha512.digest(gxyBytes);

                    byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, 32);
                    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                    byte[] hmacKeyBytes = Arrays.copyOfRange(digest, 32, 64);
                    SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");

                    byte[] iv = new byte[16];
                    SecureRandom secureRandom = new SecureRandom();
                    secureRandom.nextBytes(iv);

                    out.writeObject(iv);
                    out.flush();
                    long endCifradoAsimetrico = System.currentTimeMillis();
                    System.out.println("Tiempo para cifrar asimétricamente: " + (endCifradoAsimetrico - startCifradoAsimetrico) + " ms");

                    byte[] idCifrado = (byte[]) in.readObject();
                    byte[] hmac = (byte[]) in.readObject();
                    byte[] idPaqueteCifrado = (byte[]) in.readObject();
                    byte[] hmacPaquete = (byte[]) in.readObject();

                    IvParameterSpec ivSpec = new IvParameterSpec(iv);

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
                    byte[] idDescifrado = cipher.doFinal(idCifrado);
                    String id = new String(idDescifrado, StandardCharsets.UTF_8);

                    byte[] idPaqueteDescifrado = cipher.doFinal(idPaqueteCifrado);
                    String idPaquete = new String(idPaqueteDescifrado, StandardCharsets.UTF_8);

                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(hmacKey);

                    byte[] hmacCalculado = mac.doFinal(idDescifrado);
                    if (!Arrays.equals(hmac, hmacCalculado)) {
                        throw new SecurityException("La HMAC del ID no es válida.");
                    }

                    byte[] hmacPaqueteCalculado = mac.doFinal(idPaqueteDescifrado);
                    if (!Arrays.equals(hmacPaquete, hmacPaqueteCalculado)) {
                        throw new SecurityException("La HMAC del ID de Paquete no es válida.");
                    }

                    int idUsuario = Integer.parseInt(id);
                    int idPaqueteInt = Integer.parseInt(idPaquete);
                    int estadoPaquete = obtenerEstadoPaquete(tablaPaquetes, idUsuario, idPaqueteInt);
                    long endVerif = System.currentTimeMillis();
                    System.out.println("Tiempo para verificar la consulta: " + (endVerif - startVerif) + " ms");
                    System.out.println("(Hilo servidor " + sid + "): " + "Estado del paquete: " + estadoPaquete);
                    long startCifrado = System.currentTimeMillis();
                    Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher2.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

                    String idEstado = String.format("%d", estadoPaquete);
                    byte[] idBytes = idEstado.getBytes(StandardCharsets.UTF_8);
                    byte[] idCifradoEstado = cipher2.doFinal(idBytes);

                    mac.init(hmacKey);
                    byte[] hmacEstado = mac.doFinal(idBytes);
                    long endCifrado = System.currentTimeMillis();
                    System.out.println("Tiempo para cifrar el estado: " + (endCifrado - startCifrado) + " ms");

                    out.writeObject(idCifradoEstado);
                    out.writeObject(hmacEstado);
                    out.flush();

                    String res = (String) in.readObject();
                    if (!"TERMINAR".equals(res)) {
                        throw new IllegalArgumentException("El cliente no envió el mensaje TERMINAR.");
                    }
                    else {
                    }


                } else {
                }
                numConsultas--;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            
        }
    }

    private static byte[] descifrarReto(byte[] retoCifrado) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, K_w_minus);
        return cipher.doFinal(retoCifrado);
    }

    private static byte[] firmarTupla(BigInteger G, BigInteger P, BigInteger Gx) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(K_w_minus);
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

    public static int obtenerEstadoPaquete(ArrayList<Paquete> tabla, int idUsuario, int idPaquete) {
        for (Paquete paquete : tabla) {
            if (paquete.loginUsuario == idUsuario && paquete.idPaquete == idPaquete) {
                return paquete.estado;
            }
        }
        return -1;
    }
}

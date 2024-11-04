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

class ClientHandler implements Runnable {
    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private static PrivateKey K_w_minus;

    public ClientHandler(Socket socket, PrivateKey K_w_minus) {
        this.socket = socket;
        this.K_w_minus = K_w_minus;
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
            // 1. Leer mensaje inicial
            String mensajeInicial = (String) in.readObject();
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
                String string = "00:de:07:5c:4d:2c:2d:cb:da:0b:1c:8f:62:87:22:d7:e7:c2:9c:f6:e7:a6:b7:da:0b:57:4e:52:96:dd:d4:8f:7a:79:a5:9e:3c:8d:f4:ce:29:83:6c:75:60:ad:a2:19:5e:44:67:a3:1b:50:52:8e:bf:d0:66:bb:4f:ee:85:52:56:3b:61:16:12:82:6e:b5:1d:20:4f:7a:cc:f2:fd:3b:86:ef:7c:7d:00:b9:3d:73:e8:8f:58:0b:56:c2:41:c0:53:b4:19:ef:23:6f:c0:38:6e:f1:87:34:57:38:8e:f1:f4:a8:4d:21:ad:a3:16:7c:81:89:46:51:88:53:05:a0:cf";
                String string2 = string.replace(":", "");
                BigInteger G = new BigInteger("2");
                BigInteger P = new BigInteger(string2, 16);
                SecureRandom random = new SecureRandom();
                BigInteger x;
                
                do {
                    x = new BigInteger(P.bitLength(), random); // Generar un BigInteger aleatorio en el rango de 0 a P-1
                } while (x.compareTo(P) >= 0 || x.compareTo(BigInteger.ONE) < 0); // Asegurarse de que 1 <= x < P
                
                // Calcular G^x
                BigInteger Gx = G.modPow(x, P);

                out.writeObject(G);
                System.out.println("G enviado: " + G);
                out.writeObject(P);
                System.out.println("P enviado: " + P);
                out.writeObject(Gx);
                System.out.println("G^x enviado: " + Gx);
                byte[] firma = firmarTupla(G, P, Gx);
                System.out.println("Firma generada: " + Arrays.toString(firma));
                out.writeObject(firma);
                out.flush();

                // 10. Leer respuesta del cliente
                String respuestaCliente2 = (String) in.readObject();
                if (!"OK".equals(respuestaCliente2)) {
                    System.out.println("Cliente respondió ERROR");
                    throw new IllegalArgumentException("El cliente respondió con ERROR.");
                }

                System.out.println("Cliente respondió OK");

                BigInteger Gy = (BigInteger) in.readObject();
                BigInteger Gyx = Gy.modPow(x, P);

                byte[] gxyBytes = Gyx.toByteArray();

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

                // Generar un vector de inicialización (IV) aleatorio de 16 bytes
                byte[] iv = new byte[16];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(iv);
            } else {
                System.out.println("Cliente respondió ERROR");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
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
}

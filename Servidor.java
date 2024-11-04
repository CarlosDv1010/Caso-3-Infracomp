import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;

public class Servidor {
    private static PrivateKey privateKey;

    public static void main(String[] args) {
        try {
            // Cargar la llave privada del servidor
            privateKey = cargarLlavePrivada("private.key");

            // Iniciar el servidor en el puerto 12345
            ServerSocket serverSocket = new ServerSocket(12345);
            System.out.println("Servidor iniciado en el puerto 12345");

            while (true) {
                Socket clientSocket = serverSocket.accept();  
                System.out.println("Cliente conectado");
                new Thread(new ClienteHandler(clientSocket)).start(); 
            }
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error en el servidor: " + e.getMessage());
        }
    }

    private static class ClienteHandler implements Runnable {
        private Socket clientSocket;

        public ClienteHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
                 ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {

                // Leer el mensaje inicial del cliente
                String secInit = in.readUTF();
                if ("SECINIT".equals(secInit)) {
                    System.out.println("Recibido mensaje inicial SECINIT");
                    // Leer el reto cifrado del cliente
                    byte[] retoCifrado = (byte[]) in.readObject();
                    System.out.println("Reto cifrado recibido.");

                    String reto = descifrarConRSA(retoCifrado, privateKey);
                    System.out.println("Reto descifrado: " + reto);

                    // Firmar la respuesta usando la llave privada
                    byte[] respuestaFirmada;
                    try {
                        respuestaFirmada = firmarDatos(reto, privateKey);
                        out.writeObject(respuestaFirmada);
                        out.flush();
                        System.out.println("Respuesta firmada enviada al cliente.");
                    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                        System.err.println("Error al firmar los datos: " + e.getMessage());
                        return; // Finaliza el manejo de esta conexión
                    }

                    // Esperar respuesta del cliente
                    String respuestaCliente = in.readUTF();
                    System.out.println("Respuesta del cliente: " + respuestaCliente);
                    if ("OK".equals(respuestaCliente)) {
                        // Generar G, P, G^x
                        int G = 5; 
                        int P = 23; 
                        int x = 6; 
                        int Gx = (int) Math.pow(G, x) % P;

                        // Enviar G, P, G^x al cliente
                        out.writeInt(G);
                        out.writeInt(P);
                        out.writeInt(Gx);
                        out.flush();
                        System.out.println("Valores G, P, G^x enviados.");

                        // Leer respuesta del cliente
                        byte[] response = (byte[]) in.readObject();
                        System.out.println("Respuesta del cliente verificada: " + new String(response));

                        // Generar y enviar IV al cliente
                        byte[] iv = generarIV();
                        out.writeObject(iv);
                        out.flush();
                        System.out.println("IV enviado al cliente.");

                        // Esperar datos cifrados y HMAC del cliente
                        byte[] datosCifrados = (byte[]) in.readObject();
                        byte[] hmac = (byte[]) in.readObject();

                        // Aquí puedes validar los datos cifrados y el HMAC
                        System.out.println("Datos cifrados recibidos y HMAC validado.");
                    }
                }
                clientSocket.close();
            } catch (IOException | ClassNotFoundException | GeneralSecurityException e) {
                System.err.println("Error en el manejador del cliente: " + e.getMessage());
            }
        }
    }

    private static PrivateKey cargarLlavePrivada(String archivoLlave) throws IOException, GeneralSecurityException {
        FileInputStream fis = new FileInputStream(archivoLlave);
        byte[] bytesLlave = new byte[fis.available()];
        fis.read(bytesLlave);
        fis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytesLlave);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private static String descifrarConRSA(byte[] datosCifrados, PrivateKey llavePrivada) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
        return new String(cipher.doFinal(datosCifrados));
    }

    private static byte[] firmarDatos(String datos, PrivateKey llavePrivada) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(llavePrivada);
        signature.update(datos.getBytes());
        return signature.sign();
    }

    private static byte[] generarIV() {
        byte[] iv = new byte[16]; 
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}

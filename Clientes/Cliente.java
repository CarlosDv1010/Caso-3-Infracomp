package Clientes;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class Cliente {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("Conectado al servidor");
            out.writeUTF("SECINIT");
            out.flush();
            System.out.println("Enviando mensaje inicial...");

            // Aquí generas un reto cifrado y lo envías
            String reto = "3fc16beab6fc8b08"; // Esto es un ejemplo, deberías generarlo dinámicamente
            byte[] retoCifrado = cifrarConRSA(reto, "Clientes/public.key");
            out.writeObject(retoCifrado);
            out.flush();
            System.out.println("Reto cifrado enviado.");

            // Leer respuesta firmada del servidor
            byte[] respuestaFirmada = (byte[]) in.readObject();
            System.out.println("Respuesta firmada recibida.");

            // Aquí puedes procesar la respuesta firmada como sea necesario
            // Por ejemplo, validar la firma o continuar con el flujo

            // Enviar OK como respuesta al servidor
            out.writeUTF("OK");
            out.flush();
            System.out.println("Respuesta del cliente: OK");

            // Continuar con la siguiente parte del protocolo...

        } catch (EOFException e) {
            System.err.println("Error de conexión: El servidor ha cerrado la conexión.");
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error en el cliente: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            System.err.println("Error de seguridad: " + e.getMessage());
        }
    }

    private static byte[] cifrarConRSA(String datos, String archivoLlavePublica) throws GeneralSecurityException, IOException {
        PublicKey publicKey = cargarLlavePublica(archivoLlavePublica);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(datos.getBytes());
    }

    private static PublicKey cargarLlavePublica(String archivoLlave) throws IOException, GeneralSecurityException {
        FileInputStream fis = new FileInputStream(archivoLlave);
        byte[] bytesLlave = new byte[fis.available()];
        fis.read(bytesLlave);
        fis.close();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesLlave);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}

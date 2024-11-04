import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class Servidor {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            System.out.println("Servidor iniciado en el puerto 12345");

            while (true) {
                try (Socket socket = serverSocket.accept();
                     ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                     ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                    System.out.println("Cliente conectado");
                    String mensajeInicial = in.readUTF();
                    System.out.println("Recibido mensaje inicial " + mensajeInicial);

                    if ("SECINIT".equals(mensajeInicial)) {
                        // Esperar reto cifrado del cliente
                        byte[] retoCifrado = (byte[]) in.readObject();
                        System.out.println("Reto cifrado recibido.");

                        // Aquí debes descifrar el reto y hacer cualquier operación necesaria
                        String retoDescifrado = descifrarConRSA(retoCifrado, "private.key");
                        System.out.println("Reto descifrado: " + retoDescifrado);

                        // Respuesta firmada
                        byte[] respuestaFirmada = firmarDatos(retoDescifrado, "private.key");
                        out.writeObject(respuestaFirmada);
                        out.flush();
                        System.out.println("Respuesta firmada enviada al cliente.");

                        // Recibir la respuesta del cliente
                        String respuestaCliente = in.readUTF();
                        System.out.println("Respuesta del cliente: " + respuestaCliente);

                        // Aquí podrías continuar con el flujo
                        // Por ejemplo, enviar valores G, P, G^x al cliente
                        String valores = "Valores G, P, G^x"; // Reemplaza esto con los valores reales
                        out.writeUTF(valores);
                        out.flush();
                    }

                } catch (IOException | ClassNotFoundException | GeneralSecurityException e) {
                    System.err.println("Error en el manejador del cliente: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Error al iniciar el servidor: " + e.getMessage());
        }
    }

    private static String descifrarConRSA(byte[] datosCifrados, String archivoLlavePrivada) throws GeneralSecurityException, IOException {
        PrivateKey privateKey = cargarLlavePrivada(archivoLlavePrivada);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] datosDescifrados = cipher.doFinal(datosCifrados);
        return new String(datosDescifrados);
    }

    private static byte[] firmarDatos(String datos, String archivoLlavePrivada) throws GeneralSecurityException, IOException {
        PrivateKey privateKey = cargarLlavePrivada(archivoLlavePrivada);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(datos.getBytes());
        return signature.sign();
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
}

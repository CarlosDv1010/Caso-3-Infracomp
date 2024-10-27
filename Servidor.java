import java.security.*;
import java.io.*;

public class Servidor {
    // Constantes de estado de los paquetes
    public static final int ENOFICINA = 0;
    public static final int RECOGIDO = 1;
    public static final int ENCLASIFICACION = 2;
    public static final int DESPACHADO = 3;
    public static final int ENENTREGA = 4;
    public static final int ENTREGADO = 5;
    public static final int DESCONOCIDO = 6;

    // Método para generar y guardar las llaves
    public static void generarClaves() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();

            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            try (FileOutputStream publicOut = new FileOutputStream("Clientes/public.key")) {
                publicOut.write(publicKey.getEncoded());
            }
            
            try (FileOutputStream privateOut = new FileOutputStream("private.key")) {
                privateOut.write(privateKey.getEncoded());
            }

            System.out.println("Las llaves se generaron y guardaron correctamente.");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error al generar las llaves RSA: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Error al guardar las llaves en archivos: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        System.out.println("Seleccione una opción:");
        System.out.println("1. Generar llaves del servidor");
        System.out.println("2. Iniciar el servidor");

        // Simulación de entrada del usuario para ejecutar la opción seleccionada
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            String option = reader.readLine();
            if ("1".equals(option)) {
                generarClaves();
            } else if ("2".equals(option)) {
                iniciarServidor();
            } else {
                System.out.println("Opción no válida.");
            }
        } catch (IOException e) {
            System.err.println("Error en la entrada del usuario: " + e.getMessage());
        }
    }

    public static void iniciarServidor() {
        // Método para iniciar el servidor (opción 2)
        System.out.println("Iniciando servidor...");
    }
}

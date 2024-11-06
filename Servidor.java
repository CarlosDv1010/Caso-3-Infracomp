import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.util.concurrent.Semaphore;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Scanner;

public class Servidor {
    private static final int PUERTO = 12345;
    private static final int RSA_KEY_SIZE = 1024; 
    private static int currentid = 0;
    private static int MAX_CONEXIONES = 32; 
    private static final Semaphore semaphore = new Semaphore(MAX_CONEXIONES);


    private static PublicKey K_w_plus;
    private static PrivateKey K_w_minus;
    private static ArrayList<Paquete> tablaPaquetes;

    public static void main(String[] args) {
        try {
            tablaPaquetes = new ArrayList<Paquete>();
            for (int i = 1; i <= 32; i++) {
                int estado = (int) (Math.random() * 7) + 1;
                tablaPaquetes.add(new Paquete(i, i, estado));
            }

            Scanner scanner = new Scanner(System.in);
            while (true) {
                System.out.println("Seleccione una opción:");
                System.out.println("1. Generar llaves");
                System.out.println("2. Iniciar servidor");
                System.out.println("3. Salir");
                int opcion = scanner.nextInt();
                scanner.nextLine(); 

                if (opcion == 1) {
                    generarLlaves();
                } else if (opcion == 2) {
                    System.out.print("Introduce el número de delegados (servidores concurrentes): ");
                    MAX_CONEXIONES = scanner.nextInt();
                    cargarLlaves();
                    iniciarServidor();
                } else if (opcion==3) {
                    System.out.println("Saliendo...");
                    break;
                }
                else {
                    System.out.println("Opción no válida.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generarLlaves() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        K_w_plus = keyPair.getPublic();
        K_w_minus = keyPair.getPrivate();

        // Guardar la llave pública
        try (FileOutputStream fos = new FileOutputStream("Clientes/public.key")) {
            fos.write(K_w_plus.getEncoded());
        }

        // Guardar la llave privada
        try (FileOutputStream fos = new FileOutputStream("private.key")) {
            fos.write(K_w_minus.getEncoded());
        }

        System.out.println("Llaves generadas y guardadas.");
    }

    private static void cargarLlaves() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        try (FileInputStream fis = new FileInputStream("Clientes/public.key")) {
            byte[] keyBytes = fis.readAllBytes();
            K_w_plus = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        }
        try (FileInputStream fis = new FileInputStream("private.key")) {
            byte[] keyBytes = fis.readAllBytes();
            K_w_minus = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
    }

    private static void iniciarServidor() {
        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor escuchando en el puerto " + PUERTO);
    
            while (true) {
                semaphore.acquireUninterruptibly(); 
                try {
                    currentid++;
                    Socket socket = serverSocket.accept();
                    System.out.println("Cliente conectado a nuevo hilo.");
    
                    Thread clientThread = new Thread(() -> {
                        try {
                            new ClientHandler(socket, K_w_minus, currentid, tablaPaquetes).run();
                        } finally {
                            try {
                                socket.close();
                            } catch (IOException e) {
                                e.printStackTrace(); 
                            }
                            semaphore.release(); 
                        }
                    });
                    clientThread.start();
                } catch (IOException e) {
                    semaphore.release(); 
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace(); 
        }
    }
    

}

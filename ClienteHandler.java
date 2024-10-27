import java.net.*;
import java.io.*;

public class ClienteHandler implements Runnable {
    private Socket clientSocket;


    public ClienteHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {
            
            // Leer los datos enviados por el cliente (identificador de cliente y paquete)
            int clientId = in.readInt();
            int packageId = in.readInt();

            // Simulación de consulta a la tabla
            int estado = consultarEstado(clientId, packageId);

            // Enviar el estado correspondiente al cliente
            out.writeInt(estado);
            out.flush();

        } catch (IOException e) {
            System.err.println("Error al manejar el cliente: " + e.getMessage());
        }
    }

    // Método para simular la consulta en la tabla de estados
    private int consultarEstado(int clientId, int packageId) {
        // Lógica para consultar en la tabla predefinida
        // Retornar DESCONOCIDO si el cliente o paquete no están en la tabla
        return 1;
    }
}

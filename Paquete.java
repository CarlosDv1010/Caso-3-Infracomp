import java.util.ArrayList;
import java.util.List;

// Clase para representar una fila de la tabla
class Paquete {
    int loginUsuario;
    int idPaquete;
    int estado;

    public Paquete(int loginUsuario, int idPaquete, int estado) {
        this.loginUsuario = loginUsuario;
        this.idPaquete = idPaquete;
        this.estado = estado;
    }

    @Override
    public String toString() {
        return "Login: " + loginUsuario + ", ID Paquete: " + idPaquete + ", Estado: " + estado;
    }
}
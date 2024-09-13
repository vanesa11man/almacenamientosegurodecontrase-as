import bcrypt


class TablaHash:
    def __init__(self, tamaño):
       
        self.tamaño = tamaño
        self.tabla = [[] for _ in range(tamaño)]  

    def funcion_hash(self, clave):
        
        return sum(ord(c) for c in clave) % self.tamaño

    def insertar(self, clave, valor):
       
        índice = self.funcion_hash(clave)
        for par in self.tabla[índice]:
            if par[0] == clave:
                par[1] = valor 
                return
     
        self.tabla[índice].append([clave, valor])

    def buscar(self, clave):
        """Busca el valor asociado a una clave en la tabla hash. Devuelve None si no se encuentra."""
        índice = self.funcion_hash(clave)
        for par in self.tabla[índice]:
            if par[0] == clave:
                return par[1]
        return None  
def generar_hash_contraseña(contraseña: str) -> bytes:
    """Genera el hash de una contraseña utilizando bcrypt y un salt aleatorio."""
    salt = bcrypt.gensalt()
    hash_contraseña = bcrypt.hashpw(contraseña.encode('utf-8'), salt)
    return hash_contraseña

def verificar_contraseña(contraseña: str, hash_almacenado: bytes) -> bool:
    """Verifica si una contraseña ingresada coincide con el hash almacenado."""
    return bcrypt.checkpw(contraseña.encode('utf-8'), hash_almacenado)



if __name__ == "__main__":
   
    tabla_hash = TablaHash(10)

   
    contraseña1 = "MiContraseñaSegura"
    contraseña2 = "OtraContraseñaFuerte"
    contraseña3 = "ContraseñaSencilla"

  
    hash_contraseña1 = generar_hash_contraseña(contraseña1)
    hash_contraseña2 = generar_hash_contraseña(contraseña2)
    hash_contraseña3 = generar_hash_contraseña(contraseña3)

    tabla_hash.insertar("usuario1", hash_contraseña1)
    tabla_hash.insertar("usuario2", hash_contraseña2)
    tabla_hash.insertar("usuario3", hash_contraseña3)

    hash_almacenado_usuario1 = tabla_hash.buscar("usuario1")
    hash_almacenado_usuario2 = tabla_hash.buscar("usuario2")
    hash_almacenado_usuario3 = tabla_hash.buscar("usuario3")

    
    print("Verificación de contraseñas:")
    if verificar_contraseña(contraseña1, hash_almacenado_usuario1):
        print("Contraseña de usuario1 es correcta.")
    else:
        print("Contraseña de usuario1 es incorrecta.")

    if verificar_contraseña(contraseña2, hash_almacenado_usuario2):
        print("Contraseña de usuario2 es correcta.")
    else:
        print("Contraseña de usuario2 es incorrecta.")

    if verificar_contraseña(contraseña3, hash_almacenado_usuario3):
        print("Contraseña de usuario3 es correcta.")
    else:
        print("Contraseña de usuario3 es incorrecta.")

   
    if verificar_contraseña("ContraseñaIncorrecta", hash_almacenado_usuario1):
        print("Contraseña incorrecta pero coincide (error).")
    else:
        print("Contraseña incorrecta no coincide (correcto).")

 
    contraseña_colision = "NuevaContraseña"
    hash_colision = generar_hash_contraseña(contraseña_colision)
    tabla_hash.insertar("usuario4", hash_colision)

   
    hash_almacenado_colision = tabla_hash.buscar("usuario4")
    if verificar_contraseña(contraseña_colision, hash_almacenado_colision):
        print("Contraseña del usuario4 es correcta y la colisión fue manejada correctamente.")

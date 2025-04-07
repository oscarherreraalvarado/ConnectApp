import firebase_admin
from firebase_admin import credentials, auth, firestore
from datetime import datetime, timezone
import socketio
import eventlet
import os

# Crear una instancia de Socket.IO
sio = socketio.Server(cors_allowed_origins="*")
app = socketio.WSGIApp(sio)

# Cargar credenciales y conectar con Firebase
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)

# Conectar con Firestore
db = firestore.client()

# Manejar la conexión de un cliente
@sio.event
def connect(sid, environ):
    print(f"Cliente conectado: {sid}")

@sio.event
def login(sid, data):
    """ Verifica el token de autenticación de Firebase """
    token = data.get("token")
    try:
        decoded_token = auth.verify_id_token(token)
        user_id = decoded_token["uid"]
        print(f"Usuario autenticado: {user_id}")

        # Guardar sesión en Firestore
        db.collection("usuarios").document(user_id).update({
            "estado": "activo",
            "ultima_conexion": datetime.utcnow()
        })

        sio.emit("login_success", {"mensaje": "Login exitoso"}, room=sid)

    except Exception as e:
        print(f"Error de autenticación: {e}")
        sio.emit("login_error", {"error": "Token inválido"}, room=sid)

@sio.event
def registrar_usuario(sid, data):
    """ Crea un nuevo usuario en Firebase Authentication """
    try:
        user = auth.create_user(
            email=data["email"],
            password=data["password"],
            display_name=data["nombre"]
        )

        db.collection("usuarios").document(user.uid).set({
            "nombre": data["nombre"],
            "email": data["email"],
            "estado": "activo",
            "ultima_conexion": datetime.utcnow()
        })

        print(f"Usuario registrado: {user.uid}")
        sio.emit("registro_exitoso", {"mensaje": "Registro exitoso"}, room=sid)

    except Exception as e:
        print(f"Error al registrar usuario: {e}")
        sio.emit("registro_error", {"error": str(e)}, room=sid)

@sio.event
def chat_usuario(sid, data):
    """ Obtiene mensajes de un chat si el usuario está autenticado """
    token = data.get("token")
    chat_id = data.get("chat_id")

    try:
        decoded_token = auth.verify_id_token(token)
        user_id = decoded_token["uid"]

        print(f"Usuario {user_id} solicitó mensajes del chat {chat_id}")

        mensajes_ref = db.collection("mensajes").document(chat_id).collection("chat")
        mensajes_snapshot = mensajes_ref.stream()

        mensajes = [doc.to_dict() for doc in mensajes_snapshot]
        sio.emit("mensajes_chat", {"mensajes": mensajes}, room=sid)

    except Exception as e:
        print("Error al obtener los mensajes:", e)
        sio.emit("error_chat", {"error": "No autorizado"}, room=sid)

#@sio.event
from datetime import datetime, timezone

def enviar_mensaje(data):
    """
    Guarda un mensaje enviado por un usuario en Firestore.cl
    Si el chat no existe, lo crea automáticamente.
    Se espera que 'data' contenga: clave1, clave2, mensaje, emisor.
    """
    chat_clave1 = data.get("clave1")
    chat_clave2 = data.get("clave2")
    mensaje_texto = data.get("mensaje")
    emisor = data.get("emisor")

    if not all([chat_clave1, mensaje_texto, emisor]):
        print("Faltan datos para guardar el mensaje")
        return

    try:
        # Verificar si el chat ya existe
        chat_ref = db.collection("mensajes").document(chat_clave1)
        #if not chat_ref.get().exists:
            # Crear el documento del chat si no existe
            #chat_ref.set({
                #"usuarios": [emisor, chat_clave2],
                #"creado_en": datetime.now(timezone.utc)
            #})
            #print(f"Chat creado entre {emisor} y {chat_clave2}")

        # Crear el mensaje
        mensaje = {
            "usuario_id": emisor,
            "mensaje": mensaje_texto,
            "timestamp": datetime.now(timezone.utc)
        }

        # Guardar el mensaje en la subcolección del chat
        chat_ref.collection("chat").add(mensaje)

        print(f"Mensaje guardado en {chat_clave1} por {emisor}")

    except Exception as e:
        print("Error al guardar el mensaje:", e)


#@socketio.on("register")
def handle_register(email, password, name):
    """Registra un nuevo usuario sin usar Socket.IO, solo para pruebas"""
    try:
        user = auth.create_user(
            email=email,
            password=password,
            display_name=name
        )

        # Guardar el nombre en la base de datos de Firebase (Opcional)
        auth.update_user(user.uid, display_name=name)

        #emit("register_response", {"status": "success", "uid": user.uid, "name": data["name"]})
        print(f"Usuario registrado: {user.uid}, Nombre: {name}")
    except Exception as e:
        print(f"Error al registrar usuario: {e}")	
        #emit("register_response", {"status": "error", "message": str(e)}) 

def obtener_usuario(email=None, uid=None):
    try:
        user = auth.get_user_by_email(email) if email else auth.get_user(uid)
        return {"uid": user.uid, "email": user.email, "name": user.display_name or "Sin nombre"}
    except Exception as e:
        return {"error": str(e)} 

@sio.on("verify_token")
def verify_token(sid, data):
    """Verifica si el token enviado por el cliente es válido."""
    token = data.get("token")

    if not token:
        sio.emit("verify_response", {"status": "error", "message": "Token requerido"}, to=sid)
        return

    try:
        # Verificar el token con Firebase
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token["uid"]

        # Obtener información del usuario
        user = auth.get_user(uid)

        # Enviar la respuesta al cliente con la información del usuario
        sio.emit("verify_response", {
            "status": "success",
            "user": {
                "uid": user.uid,
                "email": user.email,
                "displayName": user.display_name or "No tiene nombre"
            }
        }, to=sid)

    except auth.InvalidIdTokenError:
        sio.emit("verify_response", {"status": "error", "message": "Token inválido o caducado"}, to=sid)

    except Exception as e:
        sio.emit("verify_response", {"status": "error", "message": str(e)}, to=sid)

def obtener_todos_usuarios():
    """Obtiene una lista de todos los usuarios registrados en Firebase Authentication"""
    try:
        usuarios = []
        # Paginar la lista de usuarios
        page = auth.list_users()
        while page:
            for user in page.users:
                usuarios.append({
                    "uid": user.uid,
                    "email": user.email,
                    "displayName": user.display_name or "Sin nombre"
                })
            page = page.next_page_token and auth.list_users(page.next_page_token)
        
        return usuarios
    except Exception as e:
        return {"error": str(e)}

# Ejecutar el servidor
if __name__ == "__main__":
    #handle_register("test@example.com", "12345678", "Juan Pérez")
    #print(obtener_usuario(email="test@example.com"))
    print(enviar_mensaje({"clave2": "usuario3-usuario1", "clave1": "usuario3-usuario1", "mensaje": "Hola Prueba para usuario1", "emisor": "usuario3"}))
    #print(obtener_todos_usuarios()) 
    port = int(os.environ.get("PORT", 5000))
    eventlet.wsgi.server(eventlet.listen(("", port)), app)
    print(f"Servidor corriendo en el puerto {port}")
    # Para ejecutar el servidor, usa el comando: python servertest.py
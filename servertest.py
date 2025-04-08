#pip install firebase-admin

import firebase_admin
from firebase_admin import credentials, auth, firestore
from datetime import datetime, timezone
import socketio
import eventlet
import os
import requests

# Crear una instancia de Socket.IO
#sio = socketio.Server(cors_allowed_origins="*")
sio = socketio.Server(cors_allowed_origins="https://connectapp-rmk5.onrender.com")
app = socketio.WSGIApp(sio)

# Cargar credenciales y conectar con Firebase
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)

# Conectar con Firestore
db = firestore.client()

# Diccionario para almacenar SID y nombre de usuario
usuarios_conectados = {}

# Manejar la conexión de un cliente
@sio.event
def connect(sid, environ):
    print(f"Cliente conectado: {sid}")


@sio.event
def login(sid, data):
    email = data.get('email')
    password = data.get('password')

    url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyDkkiWhUgqN1OB9HCKHGiqACk-PIbpeKBI"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True  # Esto asegura que se devuelva un token seguro
    }

    # Realizamos la solicitud POST
    response = requests.post(url, json=payload)

    if response.status_code == 200:
        # Si la autenticación fue exitosa, Firebase devuelve un ID token
        data = response.json()
        id_token = data['idToken']  # El ID token se usará para validaciones posteriores
        uid = data['localId']  # El UID del usuario
        
        try:
            user_info = auth.get_user(uid)
            name = user_info.display_name or "Sin nombre"
            # Emite el evento de éxito con el ID token y el UID al cliente
            usuarios_conectados[email] = sid
            print(f"Usuario reconectado: {email} con SID: {sid}")
            # Guarda en la colección usuarios
            usuario_ref = db.collection("usuarios").document(email)
            historial_ref = usuario_ref.collection("historial_conexiones")
            historial_ref.add({
                "fecha_conexion": datetime.now(),  # Guarda la fecha y hora de conexión
                "email": email
            })
            sio.emit('login_response', {
            'status': 'success',
            'id_token': id_token,
            'uid': uid,
            'email': email,
            'name': name
        }, room=sid)
        except Exception as e:
            name = "Desconocido"
            print(f"Error al obtener el nombre del usuario: {e}")
        
    else:
        # Si hubo un error, se captura el mensaje de error
        error_message = response.json().get('error', {}).get('message', 'Error al iniciar sesión')
        
        # Emite el evento de error al cliente
        sio.emit('login_response', {'status': 'error', 'message': 'Error al iniciar sesión', 'error': error_message}, room=sid)


@sio.event
def logout(sid):
    # Buscar el email asociado a ese SID
    email = None
    for user_email, user_sid in usuarios_conectados.items():
        if user_sid == sid:
            email = user_email
            break

    if email:
        # Eliminar del diccionario
        usuarios_conectados.pop(email, None)

        # Guardar en Firestore el cierre de sesión (opcional)
        try:
            usuario_ref = db.collection("usuarios").document(email)
            historial_ref = usuario_ref.collection("historial_conexiones")
            historial_ref.add({
                "fecha_desconexion": datetime.now(),
                "email": email
            })
        except Exception as e:
            print(f"Error al guardar la desconexión: {e}")

        print(f"Usuario desconectado: {email}")
        #sio.emit('logout_response', {'status': 'success', 'message': 'Sesión cerrada correctamente'}, room=sid)
    else:
        print(f"Ocurrio un error al cerrar sesión: No se encontró el usuario para el SID {sid}")
        #sio.emit('logout_response', {'status': 'error', 'message': 'No se encontró el usuario para este SID'}, room=sid)


@sio.event
def message(sid, data):
    print(f'Mensaje recibido: {data}')
    clave1 = data['clave1']
    clave2 = data['clave2']
    mensaje = data['message']
    emisor =data['emisor']
    email = data['email']
    fecha = datetime.now(timezone.utc).isoformat()
    
    codigo = obtener_codigo_por_nombre(usuarios_conectados, email)
    guardar_mensaje(clave1, clave2, mensaje, emisor)
    #Envia los mensajes al edestinatario
    if codigo is not None:
        sio.emit("message_response", {"emisor": emisor, "mensaje": mensaje, "fecha": fecha}, to=codigo)

#Obtener SID del diccionario de usuarios conectados
def obtener_codigo_por_nombre(diccionario, nombre):
    return diccionario.get(nombre, None) 



def guardar_mensaje(chat_clave1, chat_clave2, mensaje_texto, emisor):
    """
    Guarda un mensaje enviado por un usuario en Firestore.
    Si el chat no existe, lo crea automáticamente.
    """

    try:
        chat_ref = None

        chat_ref_1 = db.collection("mensajes").document(chat_clave1)
        if chat_ref_1.get().exists:
            chat_ref = chat_ref_1
        else:
            chat_ref_2 = db.collection("mensajes").document(chat_clave2)
            if chat_ref_2.get().exists:
                chat_ref = chat_ref_2
            else:
                # Crear el chat si no existe ninguno
                chat_ref = chat_ref_1
                chat_ref.set({})
                print(f"Chat creado entre {chat_clave1} y {chat_clave2}")

        # Crear el mensaje
        mensaje = {
            "emisor": emisor,
            "mensaje": mensaje_texto,
            "fecha": datetime.now(timezone.utc)
        }

        # Guardar el mensaje
        chat_ref.collection("chat").add(mensaje)
        print(f"Mensaje guardado en {chat_ref.id} por {emisor}")

    except Exception as e:
        print("Error al guardar el mensaje:", e)




@sio.event
def obtener_chat(sid, data):
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

@sio.on("register")
def registro_chat(sid, data):
    """Registra un nuevo usuario sin usar Socket.IO, solo para pruebas"""
    try:
        user = auth.create_user(
            email=data['email'],
            password=data['password'],
            display_name=data['name']
        )

        # Guardar el nombre en la base de datos de Firebase (Opcional)
        auth.update_user(user.uid, display_name=data['name'])

        # Crear un token personalizado para el usuario
        custom_token = auth.create_custom_token(user.uid)

        # Emitir la respuesta con el token
        sio.emit("register_response", {
            "status": "success",
            "uid": user.uid,
            "name": data["name"],
            "id_token": custom_token.decode('utf-8')  # Asegúrate de decodificar el token a un string
        }, to=sid)

        print(f"Usuario registrado: {user.uid}, Nombre: {data['name']}")
    except Exception as e:
        print(f"Error al registrar usuario: {e}")
        sio.emit("register_response", {"status": "error", "message": str(e)}, to=sid)


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


        if user.email:
            usuarios_conectados[user.email] = sid
            print(f"Usuario reconectado: {user.email} con SID: {sid}")
        else:
            print("Reconexión detectada, pero falta el identificador del usuario.")
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

@sio.event
def obtener_usuarios(sid, uid):
    """Envía al cliente la lista de todos los usuarios registrados en Firebase Authentication"""
    try:
        usuarios = []
        page = auth.list_users()
        while page:
            for user in page.users:
                 if user.uid != uid:  # excluir al usuario actual
                    usuarios.append({
                        "uid": user.uid,
                        "email": user.email,
                        "displayName": user.display_name or "Sin nombre"
                    })
            page = page.next_page_token and auth.list_users(page.next_page_token)

        sio.emit('obtener_usuarios_response', {"status": "success", "usuarios": usuarios}, room=sid)

    except Exception as e:
        sio.emit('obtener_usuarios_response', {"status": "error", "message": str(e)}, room=sid)





@sio.event
def obtener_mensajes(sid, data):
    """
    Evento para obtener mensajes entre dos usuarios.
    El cliente debe enviar un objeto con 'clave1' y 'clave2'.
    """
    clave1 = data.get("clave1")
    clave2 = data.get("clave2")
    print(f"Obteniendo mensajes entre {clave1} y {clave2}")
    try:
        chat_ref = None

        chat_ref_1 = db.collection("mensajes").document(clave1)
        if chat_ref_1.get().exists:
            chat_ref = chat_ref_1
        else:
            chat_ref_2 = db.collection("mensajes").document(clave2)
            if chat_ref_2.get().exists:
                chat_ref = chat_ref_2

        if not chat_ref:
            sio.emit("obtener_mensajes_respuesta", {"error": "No existe el chat"}, to=sid)
            return

        mensajes_docs = chat_ref.collection("chat").stream()
        mensajes = [
            {
                "emisor": doc.get("emisor"),
                "mensaje": doc.get("mensaje"),
                "fecha": doc.get("fecha").isoformat() if doc.get("fecha") else None
            }
            for doc in (d.to_dict() for d in mensajes_docs)
        ]

        sio.emit("obtener_mensajes_respuesta", {"mensajes": mensajes}, to=sid)

    except Exception as e:
        print("Error en obtener_mensajes:", e)
        sio.emit("obtener_mensajes_respuesta", {"mensajes": []}, to=sid)



# Ejecutar el servidor
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    eventlet.wsgi.server(eventlet.listen(("", port)), app)
    print(f"Servidor corriendo en el puerto {port}")
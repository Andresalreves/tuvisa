from cryptography.fernet import Fernet

app = Flask(__name__)

# Asegúrate de que esta clave sea la misma que en el cliente
key = b'tu_clave_secreta_aqui'
cipher_suite = Fernet(key)

@app.route('/endpoint', methods=['POST'])
def procesar_token():
    token_encriptado = request.data
    token = cipher_suite.decrypt(token_encriptado).decode()
    
    # Aquí procesas el token como sea necesario
    
    return "Token procesado correctamente"
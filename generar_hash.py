from flask_bcrypt import Bcrypt

# Inicializa Bcrypt sin Flask
bcrypt = Bcrypt()

# Cambia esta contraseña si deseas otra
contraseña = "michael30"

# Genera el hash
hash_generado = bcrypt.generate_password_hash(contraseña).decode('utf-8')

# Muestra el hash
print(f"Contraseña: {contraseña}")
print(f"Hash generado: {hash_generado}")
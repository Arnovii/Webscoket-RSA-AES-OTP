# Guía de Uso del Proyecto


**1. Crear entorno virutal (opcional)**

py -m venv venv

**2. Instalar dependencias**

**pip install -r requirements.txt

**3. Ejecutar servidor (debe estar dentro de la carpeta server)**

py .\server.py

**4. Ejecutar cliente (debe estar dentro de la carpeta client)**

python -m http.server 8000

_________________________

# CONCEPTOS CLAVES 

## Clave simétrica

Qué es: Una misma clave se usa para cifrar y descifrar mensajes.
Analogía: como una llave que abre y cierra la misma caja.
Ejemplo: AES-128 donde cliente y servidor comparten la misma clave.

## Clave asimétrica (pública/privada)

Qué es: Par de claves relacionadas: la pública cifra y la privada descifra (o viceversa para firmas).
Analogía: la pública es una caja cerrada que cualquiera puede usar para enviar un regalo; solo el dueño de la llave privada puede abrirla.
Ejemplo: RSA.

## Handshake

Qué es: Proceso inicial para acordar parámetros seguros (claves, algoritmos, etc.) entre dos extremos antes de comunicarse.
Analogía: darse la mano y presentar credenciales antes de empezar a hablar en privado.
En el código: el intercambio rsa_pub → enc_aes es el handshake.

## Nonce

Qué es: Valor único (no repetido) usado una vez para evitar repeticiones y ataques de reproducción.
Analogía: un número de serie para cada mensaje; si se repite, algo anda mal.
Uso: se usa como IV/nonce en AES-GCM (12 bytes comúnmente).

## V (Initialization Vector)

Qué es: Vector de inicialización — tipo de nonce usado para inicializar cifrados de bloque en modos como GCM o CBC.
Relación: a veces se llama nonce; debe ser único por combinación (clave, nonce).

## Plaintext (texto plano)

Qué es: Datos originales legibles antes de cifrar.
Ejemplo: "hola mundo".

## Ciphertext (texto cifrado)

Qué es: Resultado del cifrado; ilegible sin la clave adecuada.
Ejemplo: bytes base64 enviados en {"type":"enc","data": base64(nonce||ct)}.

## Tag / Auth Tag (etiqueta de autenticación)

Qué es: Código que prueba integridad y autenticidad en modos autenticados (p. ej. GCM).
Propósito: Detectar modificaciones del ciphertext o del nonce.

## AES-GCM

Qué es: Modo de operación de AES que proporciona confidencialidad + integridad (autenticación).
Por qué usarlo: cifra y añade un tag para detectar manipulación.

## RSA

Qué es: Algoritmo de clave pública usado para cifrado y firmas; típico en handshakes para proteger claves simétricas.
Propósito en el proyecto: proteger la AES key durante el intercambio inicial.

## Clave de sesión (session key)

Qué es: Clave temporal usada durante una sesión de comunicación; suele ser simétrica.
Beneficio: cambia por sesión para limitar impacto si se compromete.

## Criptografía híbrida (hybrid crypto)

Qué es: Mezcla de criptografía asimétrica (para intercambiar claves) + simétrica (para cifrar la sesión).
Por qué: combina seguridad (RSA) y eficiencia (AES).

## OTP / TOTP (One-Time Password / Time-based OTP)

Qué es: Contraseña de un solo uso; TOTP es basada en tiempo (ej. cambia cada 30 s).
En el proyecto: el servidor genera otp_secret y cliente calcula códigos TOTP para acciones privilegiadas.

## HMAC (Hash-based Message Authentication Code)

Qué es: MAC que usa una función hash y una clave para proveer integridad y autenticación de mensajes.
Uso en TOTP: TOTP usa HMAC-SHA1 internamente para generar códigos.

## Base32

Qué es: Esquema de codificación de bytes en texto (alfabeto A–Z y 2–7).
Uso: representar secretos TOTP de forma legible (ej. JBSWY3DPEHPK3PXP).

## Integridad (Integrity)

Qué es: Garantía de que los datos no han sido alterados.
Cómo se consigue: con tags (GCM) o MACs (HMAC).

## Confidencialidad (Confidentiality)

Qué es: Garantía de que sólo las partes autorizadas pueden leer los datos.
Cómo se consigue: cifrado (AES, RSA).

## Replay attack (ataque de repetición)

Qué es: Reenvío de mensajes previamente capturados para provocar acciones no deseadas.
Mitigación: nonces, timestamps, y TOTP/contadores.
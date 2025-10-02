# server.py
# Actualizado: validate_otp + validate_resp + rich.print para logs coloreados
#
# NOTA: este archivo está pensado para **demo / testing**. En producción no imprimas secretos
# ni generes claves RSA por conexión sin un análisis previo de seguridad.

import asyncio
import json
import base64
import os
import time
import hmac
import hashlib

import websockets
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rich import print


# -----------------------------------------------------------------------------
# /* 1. Proceso RSA
#
#    En este punto se genera (en la demo, por cada conexión) un par de claves RSA
#    en el servidor. La clave pública (PEM) se envía al cliente para que cifre
#    la AES key (clave simétrica). El servidor usa la clave privada para
#    descifrar esa AES key recibida (RSA-OAEP con SHA256).
#
#    Funciones relacionadas:
#      - generate_rsa_keypair()
#      - public_key_pem()
#      - rsa_decrypt()
#
#    Nota: RSA sólo protege la transmisión de la AES key (handshake). La
#    mensajería posterior usa AES-GCM (hybrid crypto).
# */
# -----------------------------------------------------------------------------

def generate_rsa_keypair():
    """Genera un par de claves RSA (private key object)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key

def public_key_pem(public_key) -> bytes:
    """Convierte una clave pública en PEM bytes para enviarla por JSON/texto."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Descifra con RSA-OAEP(SHA256)."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# -----------------------------------------------------------------------------
# /* 2. Proceso AES (AES-GCM)
#
#    AES-GCM se usa para cifrar/descifrar:
#      - el OTP secret que el servidor comparte (enc_otp)
#      - todos los mensajes posteriores (paquetes `{'type':'enc','data': base64(nonce||ct)}`)
#
#    Funciones relacionadas:
#      - aes_encrypt(aes_key, plaintext) -> nonce||ciphertext (bytes)
#      - aes_decrypt(aes_key, payload) -> plaintext (bytes)
#
#    Nota: se usa nonce de 12 bytes (estándar). El tag viene incluido en el ciphertext
#    proporcionado por AESGCM internamente.
# */
# -----------------------------------------------------------------------------

def aes_encrypt(aes_key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    # devolvemos nonce || ciphertext (ciphertext incluye tag en AESGCM)
    return nonce + ct

def aes_decrypt(aes_key: bytes, payload: bytes) -> bytes:
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None)


# -----------------------------------------------------------------------------
# /* 3. Proceso OTP (TOTP-like)
#
#    Implementación simple tipo TOTP (RFC-like):
#      - El servidor genera un secreto base32 (80 bits aquí para demo) y lo envia
#        cifrado con AES al cliente (enc_otp).
#      - El cliente genera tokens TOTP localmente y los envía cuando quiere
#        operaciones privilegiadas.
#      - El servidor puede verificar OTPs con verify_totp() y además ofrece un
#        endpoint interno `validate_otp` para que el cliente pregunte.
#
#    Funciones relacionadas:
#      - base32_secret()
#      - totp_token()
#      - verify_totp()
#      - seconds_left_in_window()
#
#    Importante: la verificación aquí es estricta (token debe corresponder al
#    periodo actual)
# */
# -----------------------------------------------------------------------------

def base32_secret() -> str:
    """Genera un secreto en base32 (sin padding) — demo: 80 bits de entropía."""
    raw = os.urandom(10)  # 80 bits
    s = base64.b32encode(raw).decode('utf-8').rstrip("=")
    return s

def _int_to_bytes(i: int) -> bytes:
    return i.to_bytes(8, 'big')

def totp_token(secret_base32: str, for_time: int = None, step: int = 30, digits: int = 6) -> str:
    """Genera un token TOTP/ HOTP-like para el periodo indicado."""
    if for_time is None:
        for_time = int(time.time())
    # Restaurar padding base32 si es necesario
    key = base64.b32decode(secret_base32 + "=" * ((8 - len(secret_base32) % 8) % 8))
    counter = int(for_time // step)
    msg = _int_to_bytes(counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (int.from_bytes(h[offset:offset+4], 'big') & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)

def verify_totp(secret_base32: str, token: str, step: int = 30) -> bool:
    """Verifica TOTP estrictamente para la ventana actual (sin tolerancia)."""
    now = int(time.time())
    current_token = totp_token(secret_base32, for_time=now, step=step)
    return token == current_token

def seconds_left_in_window(step: int = 30) -> int:
    return step - (int(time.time()) % step)


# ------------------ WebSocket server logic ------------------

async def handler(websocket):
    peer = websocket.remote_address
    print(f"[bold green][*][/bold green] Nueva conexión: [yellow]{peer}[/yellow]")

    # Generar par RSA (por demo lo generamos por conexión; en producción persistir)
    private_key = generate_rsa_keypair()
    pub_pem = public_key_pem(private_key.public_key()).decode('utf-8')

    # 1) Enviar public key RSA al cliente
    await websocket.send(json.dumps({"type":"rsa_pub", "pem": pub_pem}))
    print("[bold green][*][/bold green] Enviada public key RSA al cliente")

    try:
        # 2) Esperar mensaje con AES key cifrada (base64)
        msg_text = await websocket.recv()
        msg = json.loads(msg_text)
        if msg.get("type") != "enc_aes":
            await websocket.send(json.dumps({"type":"error","msg":"expected enc_aes"}))
            await websocket.close()
            print("[red][!] Se esperaba 'enc_aes' como primer mensaje. Cerrando conexión.[/red]")
            return

        enc_aes_b64 = msg["data"]
        try:
            enc_aes = base64.b64decode(enc_aes_b64)
        except Exception:
            await websocket.send(json.dumps({"type":"error","msg":"invalid base64 for enc_aes"}))
            await websocket.close()
            print("[red][!] enc_aes no es base64 válido.[/red]")
            return

        try:
            aes_key = rsa_decrypt(private_key, enc_aes)
        except Exception as e:
            await websocket.send(json.dumps({"type":"error","msg":"rsa_decrypt_failed"}))
            await websocket.close()
            print(f"[red][!] rsa_decrypt_failed: {e}[/red]")
            return

        if len(aes_key) != 16:
            await websocket.send(json.dumps({"type":"error","msg":"AES key must be 16 bytes"}))
            await websocket.close()
            print(f"[red][!] AES key inválida: longitud={len(aes_key)} (se esperaba 16 bytes)[/red]")
            return
        print(f"[bold green][*][/bold green] AES key recibida y descifrada (128 bits) — len={len(aes_key)}")

        # 3) Generar OTP secret y enviarlo cifrado con AES
        otp_secret = base32_secret()
        # En demo imprimimos el secreto (NO hacerlo en producción).
        print(f"[magenta]OTP secret (base32):[/magenta] [white]{otp_secret}[/white]")

        enc_otp = aes_encrypt(aes_key, otp_secret.encode('utf-8'))
        await websocket.send(json.dumps({"type":"enc_otp", "data": base64.b64encode(enc_otp).decode('utf-8')}))
        print("[bold green][*][/bold green] Enviado OTP secret cifrado (enc_otp)")

        # 4) Mensajería cifrada (espera JSON {"type":"enc","data": base64(nonce||ct)})
        while True:
            raw = await websocket.recv()
            try:
                obj = json.loads(raw)
            except Exception:
                await websocket.send(json.dumps({"type":"error","msg":"invalid json"}))
                print("[red][!] invalid json recibido del cliente[/red]")
                continue

            if obj.get("type") != "enc":
                await websocket.send(json.dumps({"type":"error","msg":"expected enc messages"}))
                print("[yellow][!] se esperaba mensajes 'enc'[/yellow]")
                continue

            b64 = obj.get("data")
            if not b64:
                await websocket.send(json.dumps({"type":"error","msg":"missing data"}))
                print("[yellow][!] paquete 'enc' sin campo data[/yellow]")
                continue

            try:
                payload = base64.b64decode(b64)
            except Exception:
                await websocket.send(json.dumps({"type":"error","msg":"invalid base64 payload"}))
                print("[red][!] payload no es base64 válido[/red]")
                continue

            try:
                plain = aes_decrypt(aes_key, payload).decode('utf-8')
            except Exception as e:
                await websocket.send(json.dumps({"type":"error","msg":"decrypt_failed"}))
                print(f"[red][!] decrypt_failed: {e}[/red]")
                continue

            # plain es JSON con campos { action: "...", ... }
            try:
                p = json.loads(plain)
            except Exception:
                await websocket.send(json.dumps({"type":"error","msg":"plaintext not json"}))
                print("[red][!] plaintext not json[/red]")
                continue

            action = p.get("action")

            # ---------------- validate_otp: nuevo endpoint ----------------
            if action == "validate_otp":
                req_id = p.get("req_id")
                client_otp = p.get("otp")
                if not req_id:
                    resp_plain = json.dumps({"action":"validate_resp","req_id": None, "valid": False, "ttl": 0, "msg":"missing req_id"})
                    enc = aes_encrypt(aes_key, resp_plain.encode('utf-8'))
                    await websocket.send(json.dumps({"type":"enc","data": base64.b64encode(enc).decode('utf-8')}))
                    print("[yellow][!] validate_otp request sin req_id[/yellow]")
                    continue

                valid = False
                try:
                    valid = verify_totp(otp_secret, str(client_otp))
                except Exception:
                    valid = False

                ttl = seconds_left_in_window()
                resp_plain = json.dumps({"action":"validate_resp","req_id": req_id, "valid": valid, "ttl": ttl})
                enc = aes_encrypt(aes_key, resp_plain.encode('utf-8'))
                await websocket.send(json.dumps({"type":"enc","data": base64.b64encode(enc).decode('utf-8')}))

                valid_markup = "[green]True[/green]" if valid else "[red]False[/red]"
                print(f"[cyan][*][/cyan] validate_otp req_id=[yellow]{req_id}[/yellow] otp=[white]{client_otp}[/white] valid={valid_markup} ttl=[magenta]{ttl}s[/magenta]")
                continue

            # ---------------- mensajes normales y solicitudes privilegiadas ----------------
            if action == "message":
                text = p.get("text","")
                client_otp = p.get("otp")  # si cliente incluyó otp lo verificamos en servidor (doble chequeo)
                if client_otp is None:
                    # Mensaje normal (sin OTP): respuesta estándar
                    print(f"[blue][client {peer}][/blue] [green](normal message)[/green] {text}")
                    reply_plain = json.dumps({"action":"message_reply","text": f"Servidor: recibido -> {text}", "privileged": False})
                    enc_reply = aes_encrypt(aes_key, reply_plain.encode('utf-8'))
                    await websocket.send(json.dumps({"type":"enc", "data": base64.b64encode(enc_reply).decode('utf-8')}))
                else:
                    # Cliente incluyó OTP: verificar (servidor es la autoridad)
                    print(f"[blue][client {peer}][/blue] [green](message with OTP)[/green] {text} | otp=[white]{client_otp}[/white]")
                    if verify_totp(otp_secret, str(client_otp)):
                        # OTP válido -> respuesta privilegiada (incluye info extra como demo)
                        secret_payload = {
                            "action":"message_reply",
                            "text": f"Servidor (privileged): recibido -> {text}",
                            "privileged": True,
                            "secret": "FLAG{informacion_privada_demo}"
                        }
                        enc_reply = aes_encrypt(aes_key, json.dumps(secret_payload).encode('utf-8'))
                        await websocket.send(json.dumps({"type":"enc", "data": base64.b64encode(enc_reply).decode('utf-8')}))
                        print("[bold green][*][/bold green] OTP válido: entregada respuesta privilegiada.")
                    else:
                        # OTP inválido -> enviar auth_fail
                        resp_plain = json.dumps({"action":"auth_fail","msg":"invalid otp"})
                        enc = aes_encrypt(aes_key, resp_plain.encode('utf-8'))
                        await websocket.send(json.dumps({"type":"enc","data": base64.b64encode(enc).decode('utf-8')}))
                        print("[red][!] Cliente intentó OTP inválido.[/red]")
                continue

            elif action == "request_secret":
                client_otp = p.get("otp")
                if not client_otp:
                    resp_plain = json.dumps({"action":"auth_fail","msg":"missing otp"})
                    enc = aes_encrypt(aes_key, resp_plain.encode('utf-8'))
                    await websocket.send(json.dumps({"type":"enc","data": base64.b64encode(enc).decode('utf-8')}))
                    print("[yellow][!] request_secret sin otp[/yellow]")
                    continue

                if verify_totp(otp_secret, str(client_otp)):
                    secret_info = {"action":"secret_info","secret":"FLAG{informacion_privada_demo}","note":"Este es un mensaje secreto 😾"}
                    enc = aes_encrypt(aes_key, json.dumps(secret_info).encode('utf-8'))
                    await websocket.send(json.dumps({"type":"enc","data": base64.b64encode(enc).decode('utf-8')}))
                    print("[bold green][*][/bold green] Entregada info privada tras OTP válido.")
                else:
                    resp_plain = json.dumps({"action":"auth_fail","msg":"invalid otp"})
                    enc = aes_encrypt(aes_key, resp_plain.encode('utf-8'))
                    await websocket.send(json.dumps({"type":"enc","data": base64.b64encode(enc).decode('utf-8')}))
                    print("[red][!] Cliente intentó OTP inválido.[/red]")
                continue

            else:
                resp_plain = json.dumps({"action":"error","msg":"unknown action"})
                enc = aes_encrypt(aes_key, resp_plain.encode('utf-8'))
                await websocket.send(json.dumps({"type":"enc","data": base64.b64encode(enc).decode('utf-8')}))
                print(f"[yellow][!] unknown action: {action}[/yellow]")
                continue

    except (ConnectionClosedOK, ConnectionClosedError):
        print(f"[bold blue][*][/bold blue] Conexión cerrada: [yellow]{peer}[/yellow]")
    except Exception as e:
        print(f"[red][!] Error en handler: {e}[/red]")
    finally:
        try:
            await websocket.close()
        except:
            pass


# ------------------ Iniciar server ------------------

async def main():
    print("[bold green][*][/bold green] Iniciando WebSocket server en [cyan]ws://localhost:5000[/cyan]")
    async with websockets.serve(handler, "0.0.0.0", 5000):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())

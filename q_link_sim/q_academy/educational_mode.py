import streamlit as st
import numpy as np
import hashlib
import logging
import datetime
import jsonpickle # For serializing metadata
import uuid  

from q_link_sim.q_ledger.audit import get_all_events
from q_link_sim.simulator.qkd_bb84 import measure_photon
from q_link_sim.simulator.qkd_bb84 import simulate_bb84
from q_link_sim.integration.crypto_bridge import encrypt_message_with_session, decrypt_message_with_session, CryptoBridgeError
from q_link_sim.q_ledger.audit import register_event
from q_link_sim.q_sync_bridge.orchestrator import get_orchestrator_instance

logger = logging.getLogger(__name__)

def launch_educational_session(topic: str):
    """
    Launches an interactive educational session based on the selected topic.
    """
    st.subheader(f"Practica: {topic}")

    if "edu_progress" not in st.session_state or st.session_state.edu_progress.get("topic") != topic:
        st.session_state.edu_progress = {
            "topic": topic,
            "step": 0,
            "qkd_key_bits": None,
            "derived_aes_key": None,
            "orchestrator_session_id": None,
            "message_original": "",
            "message_encrypted": "",
            "message_decrypted": "",
            "score": 0,
            "session_hash": hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest(),
            "tx_hash": None # For blockchain anchoring of certificate
        }
        logger.info(f"Started new educational session for topic: {topic}")

    edu_progress = st.session_state.edu_progress

    if topic == "Protocolo BB84":
        bb84_educational_flow(edu_progress)
    elif topic == "Cifrado AES con clave QKD":
        aes_encryption_educational_flow(edu_progress)
    elif topic == "Auditoria en Blockchain":
        blockchain_audit_educational_flow(edu_progress)
    
    st.markdown("---")
    st.write(f"**Puntuacion actual:** {edu_progress['score']}")
    st.write(f"**Progreso:** Paso {edu_progress['step']}")

def bb84_educational_flow(edu_progress: dict):
    """Guides the user through the BB84 protocol simulation."""
    if edu_progress["step"] == 0:
        st.markdown("### Paso 1: Generacion de Bits y Bases")
        st.write("Alice genera una secuencia de bits aleatorios y elige una base de polarizacion aleatoria (Rectilínea '+' o Diagonal 'x') para cada bit.")
        st.write("En la vida real, esto se hace con fotones individuales.")
        
        if st.button("Generar Bits y Bases de Alice"):
            num_bits = 16 # Keep it small for educational mode
            alice_bits = np.random.randint(0, 2, num_bits)
            alice_bases = np.random.randint(0, 2, num_bits)
            edu_progress["alice_bits"] = alice_bits.tolist()
            edu_progress["alice_bases"] = alice_bases.tolist()
            edu_progress["step"] = 1
            edu_progress["score"] += 10
            st.rerun()
        
    elif edu_progress["step"] == 1:
        st.markdown("### Paso 2: Bob Elige Bases y Mide")
        st.write("Alice envia los fotones a Bob. Bob, sin saber las bases de Alice, elige sus propias bases de medicion aleatorias para cada foton.")
        st.write("Luego, mide la polarizacion de cada foton.")

        num_bits = len(edu_progress["alice_bits"])
        bob_bases = np.random.randint(0, 2, num_bits)
        
        # Simulate Bob's measurements
        bob_results = []
        for i in range(num_bits):
            # Re-create Alice's polarization for measurement simulation
            alice_polarization = ""
            if edu_progress["alice_bases"][i] == 0: # Rectilinear
                alice_polarization = "|" if edu_progress["alice_bits"][i] == 0 else "-"
            else: # Diagonal
                alice_polarization = "/" if edu_progress["alice_bits"][i] == 0 else "\\"
            
            # Measure
            result = measure_photon(alice_polarization, bob_bases[i])
            bob_results.append(result)

        edu_progress["bob_bases"] = bob_bases.tolist()
        edu_progress["bob_results"] = bob_results
        
        st.write("Bases de Bob generadas y mediciones realizadas.")
        if st.button("Continuar a Comparacion de Bases"):
            edu_progress["step"] = 2
            edu_progress["score"] += 10
            st.rerun()

    elif edu_progress["step"] == 2:
        st.markdown("### Paso 3: Comparacion Publica de Bases")
        st.write("Alice y Bob se comunican publicamente para comparar las bases que usaron. Solo mantienen los bits donde sus bases coincidieron.")
        st.write("Los bits donde las bases no coincidieron se descartan, ya que la medicion de Bob fue aleatoria.")

        alice_bases = np.array(edu_progress["alice_bases"])
        bob_bases = np.array(edu_progress["bob_bases"])
        alice_bits = np.array(edu_progress["alice_bits"])
        bob_results = np.array(edu_progress["bob_results"])

        matching_bases_indices = np.where(alice_bases == bob_bases)[0]
        compatible_key_bits = alice_bits[matching_bases_indices]

        st.write(f"Bits iniciales de Alice: {edu_progress['alice_bits']}")
        st.write(f"Bases de Alice: {['+' if b == 0 else 'x' for b in edu_progress['alice_bases']]}")
        st.write(f"Bases de Bob: {['+' if b == 0 else 'x' for b in edu_progress['bob_bases']]}")
        st.write(f"Resultados de Bob: {edu_progress['bob_results']}")
        st.write(f"Indices de bases compatibles: {matching_bases_indices.tolist()}")
        st.write(f"Bits de clave compartida (compatibles): {compatible_key_bits.tolist()}")

        edu_progress["qkd_key_bits"] = compatible_key_bits.tolist()
        edu_progress["shared_key_length"] = len(compatible_key_bits)

        if st.button("Finalizar BB84 y Derivar Clave"):
            # Derive AES key from compatible bits
            if len(compatible_key_bits) > 0:
                bit_string = ''.join(str(b) for b in compatible_key_bits)
                padded_bit_string = bit_string + '0' * ((8 - len(bit_string) % 8) % 8)
                derived_aes_key = int(padded_bit_string, 2).to_bytes(len(padded_bit_string) // 8, byteorder='big')
                if len(derived_aes_key) != 32:
                    derived_aes_key = hashlib.sha256(derived_aes_key).digest()
                edu_progress["derived_aes_key"] = derived_aes_key.hex()
            else:
                edu_progress["derived_aes_key"] = ""
            
            edu_progress["step"] = 3
            edu_progress["score"] += 20
            st.rerun()

    elif edu_progress["step"] == 3:
        st.markdown("### Paso 4: Clave Secreta Establecida!")
        st.write("¡Felicidades! Has completado la simulacion del protocolo BB84.")
        st.write(f"La longitud de la clave secreta compartida es: **{edu_progress['shared_key_length']} bits**.")
        if edu_progress["derived_aes_key"]:
            st.write(f"Clave AES derivada (hex): `{edu_progress['derived_aes_key'][:16]}...`")
        else:
            st.warning("No se pudo derivar una clave AES (pocos bits compatibles).")
        
        st.session_state.edu_session_completed = True
        st.session_state.last_completed_edu_session = {
            "topic": edu_progress["topic"],
            "score": edu_progress["score"],
            "key_length": edu_progress["shared_key_length"],
            "session_hash": edu_progress["session_hash"],
            "tx_hash": None # Will be filled if certificate is anchored
        }
        st.success("¡Practica de BB84 completada!")

def aes_encryption_educational_flow(edu_progress: dict):
    """Guides the user through AES encryption/decryption with a QKD-derived key."""
    orchestrator = get_orchestrator_instance()

    if edu_progress["step"] == 0:
        st.markdown("### Paso 1: Obtener Clave QKD del Orquestador")
        st.write("Para cifrar un mensaje, primero necesitamos una clave secreta. En un sistema real, esta clave provendría de un proceso QKD y sería gestionada por el Orquestador Q-TRUST.")
        st.write("Vamos a simular la obtencion de una clave QKD y su registro en el Orquestador.")

        if st.button("Obtener Clave QKD y Registrar en Orquestador"):
            # Simulate BB84 to get a key
            _, _, _, _, compatible_key_bits, derived_aes_key, _, shared_key_length = simulate_bb84(num_bits=256)
            
            if shared_key_length > 0:
                edu_progress["qkd_key_bits"] = compatible_key_bits.tolist()
                edu_progress["derived_aes_key"] = derived_aes_key.hex()
                edu_progress["shared_key_length"] = shared_key_length

                # Register this key with the orchestrator
                try:
                    orchestrator_result = orchestrator.assign_key_pair(
                        "Edu-Alice", "Edu-Bob", "QKD_Edu", "high",
                        key_bytes=derived_aes_key,
                        qkd_compatible_bits=compatible_key_bits.tobytes()
                    )
                    edu_progress["orchestrator_session_id"] = orchestrator_result["session_id"]
                    st.success(f"Clave QKD obtenida y registrada en Orquestador con ID: {orchestrator_result['session_id'][:8]}...")
                    edu_progress["step"] = 1
                    edu_progress["score"] += 20
                except Exception as e:
                    st.error(f"Error al registrar clave en Orquestador: {e}")
                    logger.error(f"Edu mode: Error registering key with Orchestrator: {e}", exc_info=True)
            else:
                st.error("No se pudieron generar bits compatibles para la clave QKD. Intenta de nuevo.")
            st.rerun()

    elif edu_progress["step"] == 1:
        st.markdown("### Paso 2: Cifrar Mensaje")
        st.write(f"Ahora que tenemos una clave QKD gestionada por el Orquestador (ID: {edu_progress['orchestrator_session_id'][:8]}...), podemos usarla para cifrar un mensaje.")
        st.write("La clave AES derivada es: `" + edu_progress['derived_aes_key'][:16] + "...`")

        message_input = st.text_area("Introduce el mensaje a cifrar:", value=edu_progress["message_original"], key="edu_encrypt_input")
        
        if st.button("Cifrar Mensaje"):
            if message_input:
                try:
                    encrypted_msg = encrypt_message_with_session(edu_progress["orchestrator_session_id"], message_input)
                    edu_progress["message_original"] = message_input
                    edu_progress["message_encrypted"] = encrypted_msg
                    st.success("Mensaje cifrado con exito!")
                    edu_progress["step"] = 2
                    edu_progress["score"] += 30
                except CryptoBridgeError as e:
                    st.error(f"Error al cifrar: {e}")
                    logger.error(f"Edu mode: Encryption error: {e}", exc_info=True)
            else:
                st.warning("Por favor, introduce un mensaje.")
            st.rerun()

    elif edu_progress["step"] == 2:
        st.markdown("### Paso 3: Descifrar Mensaje")
        st.write("El mensaje cifrado ha sido enviado. Ahora, el receptor (Bob) puede usar la misma clave QKD (obtenida de forma segura a traves del Orquestador) para descifrarlo.")
        st.text_area("Mensaje Cifrado (Base64):", value=edu_progress["message_encrypted"], height=100, disabled=True)
        
        if st.button("Descifrar Mensaje"):
            try:
                decrypted_msg = decrypt_message_with_session(edu_progress["orchestrator_session_id"], edu_progress["message_encrypted"])
                edu_progress["message_decrypted"] = decrypted_msg
                st.success("Mensaje descifrado con exito!")
                st.write(f"Mensaje Descifrado: **{decrypted_msg}**")
                
                if decrypted_msg == edu_progress["message_original"]:
                    st.info("¡El mensaje descifrado coincide con el original! La comunicacion fue exitosa.")
                    edu_progress["score"] += 40
                else:
                    st.error("El mensaje descifrado NO coincide con el original. Algo salio mal.")
                
                edu_progress["step"] = 3
            except CryptoBridgeError as e:
                st.error(f"Error al descifrar: {e}")
                logger.error(f"Edu mode: Decryption error: {e}", exc_info=True)
            st.rerun()

    elif edu_progress["step"] == 3:
        st.markdown("### Practica Completada!")
        st.write("Has aprendido como se utiliza una clave QKD para cifrar y descifrar mensajes de forma segura.")
        st.write(f"Mensaje Original: **{edu_progress['message_original']}**")
        st.write(f"Mensaje Descifrado: **{edu_progress['message_decrypted']}**")
        
        st.session_state.edu_session_completed = True
        st.session_state.last_completed_edu_session = {
            "topic": edu_progress["topic"],
            "score": edu_progress["score"],
            "key_length": edu_progress["shared_key_length"],
            "session_hash": edu_progress["session_hash"],
            "tx_hash": None # Will be filled if certificate is anchored
        }
        st.success("¡Practica de Cifrado AES con clave QKD completada!")

def blockchain_audit_educational_flow(edu_progress: dict):
    """Guides the user through understanding blockchain auditing."""
    if edu_progress["step"] == 0:
        st.markdown("### Paso 1: Registrar un Evento Critico")
        st.write("En sistemas de seguridad, es vital registrar eventos criticos de forma inmutable. Vamos a registrar un evento simulado de 'Inicio de Sesion QKD' en nuestro Ledger de Auditoria.")
        st.write("Este evento sera anclado a la blockchain para garantizar su inmutabilidad.")

        if st.button("Registrar Evento en Ledger y Blockchain"):
            session_id = str(uuid.uuid4())
            register_event(
                event_type="QKD_START_EDU",
                session_id=session_id,
                origin_node="Edu-Node-A",
                dest_node="Edu-Node-B",
                key_length_bits=256,
                event_metadata={"edu_step": 1, "purpose": "blockchain_demo"}
            )
            st.info("Evento registrado. Verificando anclaje en blockchain...")
            
            # Retrieve the event to get the tx_hash
            all_events = get_all_events()
            latest_event = next((e for e in all_events if e['session_id'] == session_id), None)
            
            if latest_event and latest_event['metadata'] and 'blockchain_tx_hash' in latest_event['metadata']:
                edu_progress["tx_hash"] = latest_event['metadata']['blockchain_tx_hash']
                st.success(f"Evento anclado a la blockchain! TX Hash: `{edu_progress['tx_hash'][:10]}...`")
                st.markdown(f"[Ver en Polygonscan](https://mumbai.polygonscan.com/tx/{edu_progress['tx_hash']})")
                edu_progress["step"] = 1
                edu_progress["score"] += 50
            else:
                st.warning("El evento se registro en el ledger, pero el anclaje a la blockchain fallo o no se completo. Asegurate de que tu configuracion de blockchain es correcta.")
                edu_progress["step"] = 1 # Still move forward to explain ledger
                edu_progress["score"] += 20 # Partial score
            st.rerun()

    elif edu_progress["step"] == 1:
        st.markdown("### Paso 2: Verificar Inmutabilidad")
        st.write("Una vez que un evento esta en la blockchain, es extremadamente dificil de alterar. El ledger local tambien mantiene un hash de cada entrada, creando una cadena de inmutabilidad.")
        st.write("Puedes ir a la pestaña 'Auditoria y Ledger' para ver el evento registrado y verificar la integridad de todo el ledger.")
        
        if edu_progress["tx_hash"]:
            st.markdown(f"El TX Hash de tu evento es: `{edu_progress['tx_hash']}`")
            st.markdown(f"Puedes copiarlo y buscarlo en [Polygonscan](https://mumbai.polygonscan.com/tx/{edu_progress['tx_hash']}) para ver la transaccion en la red real.")
        else:
            st.info("No se pudo obtener un TX Hash para este evento. Revisa la configuracion de tu blockchain.")

        st.session_state.edu_session_completed = True
        st.session_state.last_completed_edu_session = {
            "topic": edu_progress["topic"],
            "score": edu_progress["score"],
            "key_length": 0, # Not applicable for this topic
            "session_hash": edu_progress["session_hash"],
            "tx_hash": edu_progress["tx_hash"]
        }
        st.success("¡Practica de Auditoria en Blockchain completada!")

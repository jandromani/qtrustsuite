import streamlit as st
import networkx as nx
import numpy as np
import plotly.graph_objects as go
import logging
import os
import datetime
import pandas as pd
import plotly.express as px
import uuid
import json # For JSON export
import jsonpickle # For serializing metadata in JSON export

# FIX: Add parent directory to sys.path for module imports
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import simulator modules
from q_link_sim.simulator.network import create_quantum_network, get_node_positions
from q_link_sim.simulator.qkd_bb84 import simulate_bb84
from q_link_sim.simulator.visuals import plot_network, visualize_bb84_process, plot_key_length_evolution
from q_link_sim.integration.crypto_bridge import encrypt_message_with_session, decrypt_message_with_session, CryptoBridgeError # Updated imports

# Import Q-Ledger modules
from q_link_sim.q_ledger.audit import initialize_audit_db, register_event, get_all_events, verify_ledger_integrity
from q_link_sim.q_ledger.utils import calculate_hash # For display purposes

# Import Q-Academy modules
from q_link_sim.q_academy.educational_mode import launch_educational_session
from q_link_sim.q_academy.certificates import generate_certificate

# Import Q-Sync Bridge modules
from q_link_sim.q_sync_bridge.orchestrator import get_orchestrator_instance # New

# Configure logging for Streamlit app
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'logs', 'qlinksim.log')
from q_link_sim.logging_config import setup_logging
setup_logging(log_file_path=LOG_FILE_PATH, level=logging.DEBUG) # Set to DEBUG for more detailed logs
logger = logging.getLogger(__name__)

# Define the path for the SQLite ledger database
LEDGER_DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'q_ledger', 'ledger.db')
ORCHESTRATOR_DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'q_sync_bridge', 'orchestrator.db') # New

# Initialize the audit database on app startup
initialize_audit_db(LEDGER_DB_PATH)
# Initialize the orchestrator instance
orchestrator = get_orchestrator_instance() # This will initialize its DB

def sidebar_explanation():
    st.sidebar.header("Bienvenido al Tutor de Criptografía Cuántica y Blockchain")
    
    # Introducción general
    st.sidebar.markdown("""
        **Q-LINK SIM** es una herramienta que simula la distribución cuántica de claves (QKD) utilizando el protocolo **BB84** y proporciona un sistema de auditoría y verificación usando **Blockchain**. Vamos a explicarte cómo funciona todo esto para que puedas entenderlo a fondo.
    """)

    # ¿Qué es la Criptografía Cuántica?
    st.sidebar.header("¿Qué es la Criptografía Cuántica?")
    st.sidebar.markdown("""
        La **criptografía cuántica** es un campo de la criptografía que se basa en las leyes de la **física cuántica**. Utiliza las propiedades de las partículas subatómicas, como los fotones, para crear sistemas de comunicación que son prácticamente imposibles de interceptar sin ser detectados. Esta tecnología promete una seguridad mucho más fuerte que la criptografía tradicional.

        En la criptografía cuántica, se aprovecha la propiedad cuántica del **entrelazamiento cuántico** y la **superposición de estados**. Estos conceptos permiten que la información se cifre de tal forma que cualquier intento de interceptar la comunicación altere las partículas y sea detectado.
    """)

    # ¿Cómo Funciona el Protocolo BB84?
    st.sidebar.header("¿Cómo Funciona el Protocolo BB84?")
    st.sidebar.markdown("""
        El **protocolo BB84** es uno de los protocolos más conocidos para distribuir claves secretas entre dos partes (comúnmente llamadas Alice y Bob) de manera segura, utilizando fotones polarizados. 
        - **Alice** genera una serie de fotones en diferentes estados de polarización, los cuales representan bits binarios (0 o 1).
        - **Bob** mide estos fotones utilizando una base de polarización aleatoria.
        - Después, ambos comparan sus resultados (sin revelar la información exacta de los fotones) y se quedan con los bits donde sus bases coincidieron.

        Gracias a la naturaleza cuántica de los fotones, cualquier intento de interceptar la clave en el camino (por ejemplo, por parte de un espía, llamado **Eve**) alteraría las partículas y se detectaría, lo que permite asegurar que las claves compartidas entre Alice y Bob sean verdaderamente seguras.
        
        ¿Cómo se asegura que no haya interferencia? Gracias a las **leyes de la física cuántica**, si alguien intentara medir los fotones en tránsito, su acción afectaría el sistema y sería detectada, lo que lo convierte en un sistema extremadamente seguro para compartir información.
    """)

    # ¿Por qué Usamos Blockchain?
    st.sidebar.header("¿Por qué Usamos Blockchain?")
    st.sidebar.markdown("""
        **Blockchain** es una tecnología que garantiza la inmutabilidad y trazabilidad de los datos. En nuestro sistema, usamos Blockchain para registrar y verificar todos los eventos importantes que ocurren durante el proceso de distribución de claves cuánticas. La principal ventaja de usar Blockchain es que se asegura de que los registros no puedan ser modificados una vez que han sido almacenados.

        Con el **Ledger** de Blockchain, cada evento (como la creación de una sesión de QKD, o la verificación de integridad de una clave) es guardado en una "caja fuerte" digital, lo que permite a cualquier persona verificar que los datos no han sido alterados, incluso mucho después de que se hayan almacenado. De esta forma, podemos asegurar que las transacciones cuánticas no se han manipulado y que cada acción es válida.
    """)

    # ¿Cómo Funciona el Orquestador de Claves?
    st.sidebar.header("¿Qué es el Orquestador de Claves?")
    st.sidebar.markdown("""
        El **Orquestador de Claves** es una entidad que gestiona y organiza las claves cuánticas generadas a lo largo del proceso. Después de ejecutar el protocolo **BB84** y obtener una clave compartida entre Alice y Bob, la clave es registrada en el **Orquestador de Claves**.

        El orquestador permite la **gestión** de la clave para su uso posterior en sistemas criptográficos de alta seguridad. Por ejemplo, en sistemas de cifrado AES, donde la clave cuántica puede ser utilizada para cifrar y descifrar mensajes entre partes. Este sistema permite que diferentes aplicaciones se conecten de forma segura y confiable, utilizando claves seguras generadas mediante QKD.
    """)

    # ¿Cómo Funciona la Auditoría y la Verificación?
    st.sidebar.header("¿Cómo Funciona la Auditoría y Verificación?")
    st.sidebar.markdown("""
        Para garantizar la seguridad de todo el sistema, cada evento importante en el proceso de QKD se registra en el **Ledger** utilizando Blockchain. Esto incluye las claves generadas, las sesiones de distribución, y los intentos de cifrado o descifrado. Todo esto es parte de un proceso de auditoría que permite a los usuarios verificar que el sistema está funcionando de manera segura y conforme a las expectativas.

        Las auditorías están diseñadas para:
        - **Registrar** todos los eventos críticos relacionados con la distribución de claves.
        - **Verificar la integridad** de las claves y sesiones utilizando el **hashing** y las propiedades de la blockchain.
        - **Permitir una verificación** transparente para garantizar que las claves no hayan sido comprometidas.
    """)

    # Explicación sobre el Modo de Formación Q-Academy
    st.sidebar.header("Modo de Formación Q-Academy")
    st.sidebar.markdown("""
        **Q-Academy** es una herramienta educativa integrada que permite aprender sobre criptografía cuántica de manera interactiva. A través de **lecciones prácticas** podrás entender cómo funciona el protocolo BB84, cómo se genera la clave, y cómo utilizarla para cifrar y descifrar mensajes de forma segura.

        Al completar las lecciones, recibirás un **certificado de finalización** como reconocimiento de tu progreso.
    """)

    # Resumen Final
    st.sidebar.markdown("""
        En resumen, esta aplicación te permite **experimentar con la criptografía cuántica** y entender cómo funciona un sistema de **distribución de claves cuánticas (QKD)** usando el protocolo **BB84**. Además, integra la **blockchain** para registrar y verificar todos los eventos de seguridad de forma inmutable, asegurando la confidencialidad de las comunicaciones.
    """)

def main():
    st.set_page_config(layout="wide", page_title="Q-LINK SIM: Quantum Key Distribution Simulator")

    st.title("Q-LINK SIM: Simulador de Red Cuantica")
    st.markdown("Simulacion visual del protocolo BB84 para distribucion de claves cuanticas.")
    sidebar_explanation()  # Call the expanded explanation function
    # Initialize session state variables
    if 'graph' not in st.session_state:
        st.session_state.graph = create_quantum_network(num_nodes=5)
        st.session_state.pos = get_node_positions(st.session_state.graph)
        st.session_state.selected_source = None
        st.session_state.selected_target = None
        st.session_state.bb84_results = None
        st.session_state.shared_key_bytes = None # The 32-byte derived AES key
        st.session_state.compatible_key_bits = None # The numpy array of compatible bits
        st.session_state.sessions = [] # List to store session history (for dashboard display)
        st.session_state.current_message_original = ""
        st.session_state.current_message_encrypted = ""
        st.session_state.current_message_decrypted = ""
        st.session_state.current_session_id = None # Session ID from QKD simulation
        st.session_state.current_orchestrator_session_id = None # Session ID from Orchestrator
        st.session_state.last_qkd_num_bits = 128 # Store last used QKD bits for repeat session
        st.session_state.edu_progress = {} # For educational mode progress
        st.session_state.edu_session_completed = False # Flag for certificate button
        st.session_state.last_completed_edu_session = None # Data for certificate

    # --- Sidebar for Session Management ---
    st.sidebar.header("Gestion de Sesiones QKD")
    if st.sidebar.button("Crear nueva sesion QKD"):
        st.session_state.selected_source = None
        st.session_state.selected_target = None
        st.session_state.bb84_results = None
        st.session_state.shared_key_bytes = None
        st.session_state.compatible_key_bits = None
        st.session_state.current_message_original = ""
        st.session_state.current_message_encrypted = ""
        st.session_state.current_message_decrypted = ""
        st.session_state.current_session_id = None
        st.session_state.current_orchestrator_session_id = None # Clear orchestrator session too
        st.sidebar.success("Nueva sesion QKD iniciada. Selecciona nodos y ejecuta BB84.")
        logger.info("New QKD session initiated from UI sidebar.")
        st.rerun()

    st.sidebar.subheader("Historial de Sesiones")
    # Reload sessions from Streamlit's session_state for display
    sessions_df = pd.DataFrame(st.session_state.sessions)
    
    if not sessions_df.empty:
        # Filters
        filter_ok = st.sidebar.checkbox("Mostrar OK", value=True, key="filter_ok")
        filter_error = st.sidebar.checkbox("Mostrar ERROR", value=True, key="filter_error")
        filter_encrypted = st.sidebar.checkbox("Mostrar Cifrado", value=True, key="filter_encrypted")

        filtered_df = sessions_df[
            ((sessions_df['Estado'] == 'OK') & filter_ok) |
            ((sessions_df['Estado'] == 'ERROR') & filter_error) |
            ((sessions_df['Estado'] == 'Cifrado') & filter_encrypted)
        ]

        for index, session in filtered_df.iterrows():
            status_text = "OK" if session['Estado'] == "OK" else ("ERROR" if session['Estado'] == "ERROR" else "Cifrado")
            st.sidebar.write(f"{status_text} | ID: {session['ID'][:8]}... | {session['Origen']} -> {session['Destino']} | {session['Longitud Clave (bits)']} bits | {session['Estado']}")
            
            # "Repeat Session" button
            if st.sidebar.button(f"Repetir sesion {session['ID'][:8]}...", key=f"repeat_{session['ID']}"):
                st.session_state.selected_source = session['Origen']
                st.session_state.selected_target = session['Destino']
                st.session_state.last_qkd_num_bits = session['Longitud Clave (bits)'] if session['Estado'] != 'ERROR' else 128 # Use previous bits or default
                st.session_state.bb84_results = None # Clear previous results to re-run
                st.session_state.shared_key_bytes = None
                st.session_state.compatible_key_bits = None
                st.session_state.current_message_original = ""
                st.session_state.current_message_encrypted = ""
                st.session_state.current_message_decrypted = ""
                st.session_state.current_session_id = None # New session ID will be generated
                st.session_state.current_orchestrator_session_id = None # Clear orchestrator session too
                st.sidebar.info(f"Cargando sesion {session['ID'][:8]} para repetir.")
                logger.info(f"Repeating QKD session {session['ID']} from UI sidebar.")
                st.rerun()
    else:
        st.sidebar.info("No hay sesiones QKD anteriores.")

    # --- Main Content ---
    tab1, tab2, tab3, tab4 = st.tabs(["Simulador de Red", "Auditoria y Ledger", "Modo Formacion", "Orquestador Q-TRUST"])

    with tab1:
        graph = st.session_state.graph
        pos = st.session_state.pos

        st.header("1. Configuracion de la Red Cuantica")
        num_nodes_option = st.slider("Numero de Nodos en la Red", 3, 6, len(graph.nodes))
        if num_nodes_option != len(graph.nodes):
            st.session_state.graph = create_quantum_network(num_nodes=num_nodes_option)
            st.session_state.pos = get_node_positions(st.session_state.graph)
            st.session_state.selected_source = None
            st.session_state.selected_target = None
            st.session_state.bb84_results = None # Reset results on network change
            st.session_state.shared_key_bytes = None
            st.session_state.compatible_key_bits = None
            st.session_state.current_message_original = ""
            st.session_state.current_message_encrypted = ""
            st.session_state.current_message_decrypted = ""
            st.session_state.current_session_id = None
            st.session_state.current_orchestrator_session_id = None
            logger.info(f"Network changed to {num_nodes_option} nodes.")
            st.rerun()

        # Display the network graph
        fig = plot_network(graph, pos, (st.session_state.selected_source, st.session_state.selected_target))
        st.plotly_chart(fig, use_container_width=True)

        # Node selection
        nodes = list(graph.nodes())
        col1, col2 = st.columns(2)
        with col1:
            # Set default index for selectbox to avoid error if selected_source is not in nodes
            default_source_idx = nodes.index(st.session_state.selected_source) if st.session_state.selected_source in nodes else 0
            st.session_state.selected_source = st.selectbox("Nodo Origen (Alice)", nodes, index=default_source_idx)
        with col2:
            available_targets = [n for n in nodes if n != st.session_state.selected_source]
            # Set default index for target, ensuring it's valid
            default_target_idx = available_targets.index(st.session_state.selected_target) if st.session_state.selected_target in available_targets else (0 if available_targets else None)
            st.session_state.selected_target = st.selectbox("Nodo Destino (Bob)", available_targets, index=default_target_idx)

        # Check if selected nodes are connected
        if st.session_state.selected_source and st.session_state.selected_target:
            if not graph.has_edge(st.session_state.selected_source, st.session_state.selected_target):
                st.warning(f"Los nodos {st.session_state.selected_source} y {st.session_state.selected_target} no estan conectados directamente. La simulacion de QKD asume una conexion directa.")
            else:
                st.success(f"Nodos {st.session_state.selected_source} y {st.session_state.selected_target} seleccionados y conectados.")

        st.header("2. Simulacion del Protocolo BB84")
        num_bits_qkd = st.slider("Numero de bits a enviar (para simulacion BB84)", 64, 512, st.session_state.last_qkd_num_bits, step=64)

        if st.button("Ejecutar QKD (simulacion BB84)"):
            if st.session_state.selected_source and st.session_state.selected_target:
                st.info(f"Simulando QKD entre {st.session_state.selected_source} (Alice) y {st.session_state.selected_target} (Bob) con {num_bits_qkd} bits...")
                
                session_id = str(uuid.uuid4())
                st.session_state.current_session_id = session_id
                st.session_state.last_qkd_num_bits = num_bits_qkd # Update last used bits

                register_event(
                    event_type="QKD_START",
                    session_id=session_id,
                    origin_node=st.session_state.selected_source,
                    dest_node=st.session_state.selected_target,
                    key_length_bits=num_bits_qkd,
                    event_metadata={"raw_bits_attempted": num_bits_qkd}
                )

                try:
                    (
                        alice_bits,
                        alice_bases,
                        bob_bases,
                        bob_results,
                        compatible_key_bits,
                        derived_aes_key, # This is the 32-byte key
                        raw_key_length,
                        shared_key_length
                    ) = simulate_bb84(num_bits=num_bits_qkd)

                    st.session_state.bb84_results = {
                        "alice_bits": alice_bits,
                        "alice_bases": alice_bases,
                        "bob_bases": bob_bases,
                        "bob_results": bob_results,
                        "compatible_key_bits": compatible_key_bits,
                        "raw_key_length": raw_key_length,
                        "shared_key_length": shared_key_length
                    }
                    st.session_state.shared_key_bytes = derived_aes_key # Store the derived AES key
                    st.session_state.compatible_key_bits = compatible_key_bits # Store the bits for crypto bridge
                    st.success("Simulacion BB84 completada con exito!")
                    logger.info(f"BB84 simulation run between {st.session_state.selected_source} and {st.session_state.selected_target}. Shared key length: {shared_key_length}")

                    # Add successful session to history and ledger
                    st.session_state.sessions.append({
                        "ID": session_id,
                        "Origen": st.session_state.selected_source,
                        "Destino": st.session_state.selected_target,
                        "Longitud Clave (bits)": shared_key_length,
                        "Timestamp": datetime.datetime.now(),
                        "Estado": "OK",
                        "Mensaje Original": None,
                        "Mensaje Cifrado": None,
                        "Clave BB84 (bits)": compatible_key_bits.tolist() # Store as list for JSON compatibility
                    })
                    register_event(
                        event_type="QKD_SUCCESS",
                        session_id=session_id,
                        origin_node=st.session_state.selected_source,
                        dest_node=st.session_state.selected_target,
                        key_length_bits=shared_key_length,
                        event_metadata={"raw_bits_sent": raw_key_length, "compatible_bits_array_len": len(compatible_key_bits)}
                    )

                    # Automatically assign an orchestrator session for this QKD key
                    if st.session_state.shared_key_bytes:
                        try:
                            orchestrator_result = orchestrator.assign_key_pair(
                                st.session_state.selected_source,
                                st.session_state.selected_target,
                                "QKD_Sim", # System type for QKD simulation
                                "high", # Priority for QKD keys
                                key_bytes=st.session_state.shared_key_bytes, # Pass the derived key
                                qkd_compatible_bits=st.session_state.compatible_key_bits.tobytes() # Pass compatible bits for storage
                            )
                            st.session_state.current_orchestrator_session_id = orchestrator_result["session_id"]
                            st.info(f"Clave QKD registrada en Orquestador Q-TRUST con ID: {st.session_state.current_orchestrator_session_id[:8]}...")
                        except Exception as e:
                            st.warning(f"No se pudo registrar la clave QKD en el Orquestador: {e}")
                            logger.error(f"Failed to register QKD key with Orchestrator: {e}", exc_info=True)


                except Exception as e:
                    st.error(f"Error durante la simulacion BB84: {e}")
                    logger.error(f"Error during BB84 simulation for session {session_id}: {e}", exc_info=True)
                    # Add failed session to history and ledger
                    st.session_state.sessions.append({
                        "ID": session_id,
                        "Origen": st.session_state.selected_source,
                        "Destino": st.session_state.selected_target,
                        "Longitud Clave (bits)": 0, # Indicate failure
                        "Timestamp": datetime.datetime.now(),
                        "Estado": "ERROR",
                        "Mensaje Original": None,
                        "Mensaje Cifrado": None,
                        "Clave BB84 (bits)": []
                    })
                    register_event(
                        event_type="QKD_ERROR",
                        session_id=session_id,
                        origin_node=st.session_state.selected_source,
                        dest_node=st.session_state.selected_target,
                        key_length_bits=0,
                        event_metadata={"error_message": str(e), "raw_bits_attempted": num_bits_qkd}
                    )
            else:
                st.error("Por favor, selecciona los nodos Origen y Destino primero.")

        # --- Display BB84 Results ---
        if st.session_state.bb84_results:
            results = st.session_state.bb84_results
            st.subheader("Resultados de la Simulacion BB84")

            st.write(f"**Bits enviados por Alice (Raw Key Length):** {results['raw_key_length']}")
            st.write(f"**Bits compatibles (Shared Key Length):** {results['shared_key_length']}")
            if st.session_state.shared_key_bytes:
                st.write(f"**Clave AES Derivada (32 bytes):** `{st.session_state.shared_key_bytes.hex()}`")
            st.write(f"**Clave Compatible (bits, truncada):** `{str(results['compatible_key_bits'][:20])}...{str(results['compatible_key_bits'][-20:])}`")

            st.markdown("---")
            st.subheader("Detalle Paso a Paso del Protocolo BB84")
            
            # Create a DataFrame for detailed visualization
            bb84_df = visualize_bb84_process(
                results['alice_bits'],
                results['alice_bases'],
                results['bob_bases'],
                results['bob_results'],
                results['compatible_key_bits']
            )
            st.dataframe(bb84_df, use_container_width=True)

            st.markdown("---")
            st.header("3. Cifrado y Descifrado con Clave BB84")

            if st.session_state.current_orchestrator_session_id:
                message_to_encrypt = st.text_area("Mensaje a Cifrar:", value=st.session_state.current_message_original, height=100, key="encrypt_message_input")
                
                if st.button("Cifrar con clave BB84"):
                    if message_to_encrypt:
                        try:
                            encrypted_text = encrypt_message_with_session(st.session_state.current_orchestrator_session_id, message_to_encrypt)
                            st.session_state.current_message_original = message_to_encrypt
                            st.session_state.current_message_encrypted = encrypted_text
                            st.success("Mensaje cifrado con exito!")
                            logger.info(f"Message encrypted using BB84 key for session {st.session_state.current_session_id}")
                            
                            # Update session history with encryption details
                            if st.session_state.current_session_id:
                                for session in st.session_state.sessions:
                                    if session["ID"] == st.session_state.current_session_id:
                                        session["Estado"] = "Cifrado"
                                        session["Mensaje Original"] = message_to_encrypt
                                        session["Mensaje Cifrado"] = encrypted_text
                                        break
                            register_event(
                                event_type="CIPHER_ENCRYPT",
                                session_id=st.session_state.current_session_id,
                                origin_node=st.session_state.selected_source,
                                dest_node=st.session_state.selected_target,
                                key_length_bits=st.session_state.bb84_results['shared_key_length'],
                                message_content=message_to_encrypt,
                                event_metadata={"ciphertext_len": len(encrypted_text), "orchestrator_session_id": st.session_state.current_orchestrator_session_id}
                            )
                            st.rerun()
                        except CryptoBridgeError as e:
                            st.error(f"Error al cifrar el mensaje: {e}")
                            logger.error(f"Encryption error for session {st.session_state.current_session_id}: {e}", exc_info=True)
                            register_event(
                                event_type="CIPHER_ERROR",
                                session_id=st.session_state.current_session_id,
                                origin_node=st.session_state.selected_source,
                                dest_node=st.session_state.selected_target,
                                key_length_bits=st.session_state.bb84_results['shared_key_length'],
                                message_content=message_to_encrypt,
                                event_metadata={"error_message": str(e), "action": "encrypt", "orchestrator_session_id": st.session_state.current_orchestrator_session_id}
                            )
                    else:
                        st.warning("Por favor, introduce un mensaje para cifrar.")
                
                if st.session_state.current_message_encrypted:
                    st.text_area("Mensaje Cifrado (Base64):", value=st.session_state.current_message_encrypted, height=150, key="encrypted_output", disabled=True)
                    
                    ciphertext_to_decrypt = st.text_area("Pegar Ciphertext para Descifrar:", value=st.session_state.current_message_encrypted, height=150, key="decrypt_ciphertext_input")
                    
                    if st.button("Descifrar con clave BB84"):
                        if ciphertext_to_decrypt:
                            try:
                                decrypted_text = decrypt_message_with_session(st.session_state.current_orchestrator_session_id, ciphertext_to_decrypt)
                                st.session_state.current_message_decrypted = decrypted_text
                                st.success("Mensaje descifrado con exito!")
                                logger.info(f"Message decrypted using BB84 key for session {st.session_state.current_session_id}")
                                register_event(
                                    event_type="CIPHER_DECRYPT",
                                    session_id=st.session_state.current_session_id,
                                    origin_node=st.session_state.selected_target, # Bob decrypts
                                    dest_node=st.session_state.selected_source, # Alice sent
                                    key_length_bits=st.session_state.bb84_results['shared_key_length'],
                                    message_content=decrypted_text, # Hash of decrypted content
                                    event_metadata={"ciphertext_len": len(ciphertext_to_decrypt), "orchestrator_session_id": st.session_state.current_orchestrator_session_id}
                                )
                                st.rerun()
                            except CryptoBridgeError as e:
                                st.error(f"Error al descifrar el mensaje: {e}")
                                logger.error(f"Decryption error for session {st.session_state.current_session_id}: {e}", exc_info=True)
                                register_event(
                                    event_type="CIPHER_ERROR",
                                    session_id=st.session_state.current_session_id,
                                    origin_node=st.session_state.selected_target,
                                    dest_node=st.session_state.selected_source,
                                    key_length_bits=st.session_state.bb84_results['shared_key_length'],
                                    message_content=ciphertext_to_decrypt, # Hash of ciphertext on error
                                    event_metadata={"error_message": str(e), "action": "decrypt", "orchestrator_session_id": st.session_state.current_orchestrator_session_id}
                                )
                        else:
                            st.warning("Por favor, pega el ciphertext para descifrar.")
                    
                    if st.session_state.current_message_decrypted:
                        st.text_area("Mensaje Descifrado:", value=st.session_state.current_message_decrypted, height=100, key="decrypted_output", disabled=True)
                        if st.session_state.current_message_decrypted == st.session_state.current_message_original:
                            st.info("El mensaje descifrado coincide con el original.")
                        else:
                            st.error("El mensaje descifrado NO coincide con el original. Posible error en la clave o el proceso.")
            else:
                st.info("Ejecuta la simulacion BB84 para generar una clave y asignarla al Orquestador antes de cifrar/descifrar.")

        st.markdown("---")
        st.header("Dashboard de Sesiones QKD")
        if not sessions_df.empty:
            sessions_df_display = sessions_df.copy()
            # Format Timestamp for display
            sessions_df_display['Timestamp'] = sessions_df_display['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            # Select and reorder columns for display
            display_cols = ["ID", "Origen", "Destino", "Longitud Clave (bits)", "Timestamp", "Estado"]
            st.dataframe(sessions_df_display[display_cols], use_container_width=True)

            st.subheader("Evolucion de la Longitud de Clave Compartida")
            fig_evolution = plot_key_length_evolution(sessions_df_display)
            st.plotly_chart(fig_evolution, use_container_width=True)
        else:
            st.info("No hay datos de sesiones para mostrar en el dashboard.")

    with tab2:
        st.header("Auditoria y Ledger")
        st.markdown("Todos los eventos criticos de la red cuantica simulada son registrados aqui de forma inmutable y verificable.")

        all_ledger_events = get_all_events()
        ledger_df = pd.DataFrame(all_ledger_events)
        ledger_df['decoded_metadata'] = ledger_df['metadata'].apply(
        lambda x:
            jsonpickle.decode(x) if isinstance(x, str) and x else
            (x if isinstance(x, dict) else {})
    )

        if not ledger_df.empty:
            # Filtering options
            st.subheader("Filtros de Eventos")
            col_filter1, col_filter2, col_filter3 = st.columns(3)
            with col_filter1:
                event_types = ["Todos"] + sorted(ledger_df['event_type'].unique().tolist())
                selected_event_type = st.selectbox("Tipo de Evento", event_types)
            with col_filter2:
                nodes = ["Todos"] + sorted(pd.concat([ledger_df['origin_node'], ledger_df['dest_node']]).dropna().unique().tolist())
                selected_node = st.selectbox("Nodo (Origen/Destino)", nodes)
            with col_filter3:
                # Ensure date_input handles None for initial value if no events
                default_start_date = datetime.date.today() - datetime.timedelta(days=7)
                default_end_date = datetime.date.today()
                if not ledger_df.empty:
                    min_date = pd.to_datetime(ledger_df['timestamp']).min().date()
                    max_date = pd.to_datetime(ledger_df['timestamp']).max().date()
                    default_start_date = max(min_date, default_start_date)
                    default_end_date = max_date
                
                date_range = st.date_input("Rango de Fechas", value=(default_start_date, default_end_date))
            
            filtered_ledger_df = ledger_df.copy()
            if selected_event_type != "Todos":
                filtered_ledger_df = filtered_ledger_df[filtered_ledger_df['event_type'] == selected_event_type]
            if selected_node != "Todos":
                filtered_ledger_df = filtered_ledger_df[(filtered_ledger_df['origin_node'] == selected_node) | (filtered_ledger_df['dest_node'] == selected_node)]
            
            if len(date_range) == 2:
                start_date, end_date = date_range
                filtered_ledger_df['timestamp_dt'] = pd.to_datetime(filtered_ledger_df['timestamp'])
                filtered_ledger_df = filtered_ledger_df[
                    (filtered_ledger_df['timestamp_dt'].dt.date >= start_date) &
                    (filtered_ledger_df['timestamp_dt'].dt.date <= end_date)
                ]
                filtered_ledger_df = filtered_ledger_df.drop(columns=['timestamp_dt']) # Clean up temp column

            st.subheader("Eventos en el Ledger")
            # Display selected columns for readability
            display_cols_ledger = [
                "timestamp", "event_type", "session_id", "origin_node", 
                "dest_node", "key_length_bits", "message_hash", "entry_hash"
            ]
            
            # Check if 'blockchain_tx_hash' exists in any metadata before adding column
            # Need to decode metadata first to check its content
            ledger_df['decoded_metadata'] = ledger_df['metadata'].apply(
    lambda x:                                   # x puede ser None, str o dict
        jsonpickle.decode(x) if isinstance(x, str) and x else
        (x if isinstance(x, dict) else {})
)
            if any('blockchain_tx_hash' in meta for meta in ledger_df['decoded_metadata']):
                filtered_ledger_df['Blockchain TX'] = filtered_ledger_df['decoded_metadata'].apply(
                    lambda x: x.get('blockchain_tx_hash') if x and 'blockchain_tx_hash' in x else ''
                )
                display_cols_ledger.append('Blockchain TX')
            
            st.dataframe(filtered_ledger_df[display_cols_ledger], use_container_width=True)

            # Display Blockchain TX as clickable links below the table
            st.markdown("---")
            st.subheader("Enlaces de Transaccion Blockchain")
            tx_hashes_displayed = set()
            for index, row in filtered_ledger_df.iterrows():
                tx_hash = row.get('Blockchain TX')
                if tx_hash and tx_hash not in tx_hashes_displayed:
                    st.markdown(f"**{row['event_type']}** (Session {row['session_id'][:8]}...): "
                                f"[https://mumbai.polygonscan.com/tx/{tx_hash}](https://mumbai.polygonscan.com/tx/{tx_hash})")
                    tx_hashes_displayed.add(tx_hash)
            if not tx_hashes_displayed:
                st.info("No hay transacciones blockchain para mostrar en los filtros actuales.")


            st.subheader("Opciones de Auditoria")
            col_audit1, col_audit2 = st.columns(2)
            with col_audit1:
                # Export to JSON
                export_data = filtered_ledger_df.to_dict(orient='records')
                # jsonpickle.encode handles numpy arrays and other complex types
                json_export_string = jsonpickle.encode(export_data, indent=2)
                st.download_button(
                    label="Exportar a JSON",
                    data=json_export_string,
                    file_name="q_ledger_events.json",
                    mime="application/json"
                )
            with col_audit2:
                # Verify Integrity
                if st.button("Verificar integridad"):
                    # Need to load the raw data from DB to verify, not the filtered/displayed df
                    # Or, ensure the exported_data is used for verification
                    # For simplicity, let's re-fetch all events for verification
                    # In a real scenario, you'd upload the JSON and verify that.
                    all_events_from_db = get_all_events()
                    if verify_ledger_integrity(all_events_from_db):
                        st.success("Todos los registros verificados. Integridad confirmada.")
                    else:
                        st.error("Fallo en la verificacion de integridad. Algunos registros han sido alterados.")
        else:
            st.info("No hay eventos registrados en el ledger aun.")

    with tab3:
        st.header("Modo Formacion: Q-Academy Live")
        st.markdown("Aprende los fundamentos de la criptografia cuantica y la seguridad con ejercicios interactivos.")

        educational_topics = {
            "Protocolo BB84": "Aprende como Alice y Bob establecen una clave secreta usando fotones polarizados.",
            "Cifrado AES con clave QKD": "Descubre como la clave cuantica se usa para cifrar y descifrar mensajes reales.",
            "Auditoria en Blockchain": "Entiende como la blockchain proporciona inmutabilidad y trazabilidad a los eventos de seguridad."
        }

        selected_topic = st.selectbox("Selecciona un Tema de Practica:", list(educational_topics.keys()))
        st.info(educational_topics[selected_topic])

        if st.button("Comenzar Practica"):
            st.session_state.edu_session_completed = False # Reset completion flag
            launch_educational_session(selected_topic)
            st.rerun()

        if st.session_state.edu_progress and st.session_state.edu_progress.get("topic") == selected_topic:
            # This ensures the educational flow continues on rerun
            launch_educational_session(selected_topic)
        
        # Certificate generation button
        if st.session_state.edu_session_completed and st.session_state.last_completed_edu_session:
            st.markdown("---")
            st.subheader("Sesion Educativa Completada!")
            st.write(f"Tema: {st.session_state.last_completed_edu_session['topic']}")
            st.write(f"Puntuacion: {st.session_state.last_completed_edu_session['score']} puntos")
            st.write(f"Longitud de clave obtenida: {st.session_state.last_completed_edu_session['key_length']} bits")
            
            if st.session_state.last_completed_edu_session['tx_hash']:
                st.write(f"TX hash: `{st.session_state.last_completed_edu_session['tx_hash'][:10]}...`")
                st.markdown(f"[Ver en Polygonscan](https://mumbai.polygonscan.com/tx/{st.session_state.last_completed_edu_session['tx_hash']})")

            st.markdown("---")
            st.info("Descarga tu certificado de finalizacion!")
            student_name = st.text_input("Introduce tu nombre para el certificado:", key="cert_name_input")
            
            if st.button("Generar Certificado PDF"):
                if student_name:
                    try:
                        cert_path = generate_certificate(
                            name=student_name,
                            topic=st.session_state.last_completed_edu_session['topic'],
                            score=st.session_state.last_completed_edu_session['score'],
                            key_length=st.session_state.last_completed_edu_session['key_length'],
                            session_hash=st.session_state.last_completed_edu_session['session_hash'],
                            tx_hash=st.session_state.last_completed_edu_session['tx_hash']
                        )
                        st.success(f"Certificado generado: {os.path.basename(cert_path)}")
                        with open(cert_path, "rb") as file:
                            st.download_button(
                                label="Descargar Certificado",
                                data=file.read(),
                                file_name=os.path.basename(cert_path),
                                mime="application/pdf"
                            )
                        st.session_state.edu_session_completed = False # Reset to prevent re-generation on refresh
                        st.session_state.last_completed_edu_session = None
                    except Exception as e:
                        st.error(f"Error al generar el certificado: {e}")
                        logger.error(f"Certificate generation error: {e}", exc_info=True)
                else:
                    st.warning("Por favor, introduce tu nombre para generar el certificado.")

    with tab4: # New Orchestrator Tab
        st.header("Orquestador Q-TRUST")
        st.markdown("El orquestador gestiona las sesiones de clave cuantica y post-cuantica para diferentes sistemas segun su criticidad.")

        active_orchestrator_sessions = orchestrator.get_active_sessions()
        orchestrator_df = pd.DataFrame(active_orchestrator_sessions)

        if not orchestrator_df.empty:
            # Convert bytes to hex for display
            orchestrator_df['symmetric_key_hex'] = orchestrator_df['symmetric_key'].apply(lambda x: x.hex() if x else None)
            orchestrator_df['qkd_compatible_bits_len'] = orchestrator_df['qkd_compatible_bits'].apply(lambda x: len(x) if x is not None else 0)
            orchestrator_df['expires_at_str'] = orchestrator_df['expires_at'].dt.strftime('%Y-%m-%d %H:%M:%S')
            orchestrator_df['created_at_str'] = orchestrator_df['created_at'].dt.strftime('%Y-%m-%d %H:%M:%S')

            st.subheader("Sesiones Activas del Orquestador")
            
            # Filters
            col_orch_filter1, col_orch_filter2, col_orch_filter3 = st.columns(3)
            with col_orch_filter1:
                system_types = ["Todos"] + sorted(orchestrator_df['system_type'].unique().tolist())
                selected_system_type = st.selectbox("Tipo de Sistema", system_types, key="orch_filter_system")
            with col_orch_filter2:
                key_types = ["Todos"] + sorted(orchestrator_df['key_type'].unique().tolist())
                selected_key_type = st.selectbox("Tipo de Clave", key_types, key="orch_filter_key")
            with col_orch_filter3:
                priority_levels = ["Todos"] + sorted(orchestrator_df['priority_level'].unique().tolist())
                selected_priority_level = st.selectbox("Nivel de Prioridad", priority_levels, key="orch_filter_priority")

            filtered_orch_df = orchestrator_df.copy()
            if selected_system_type != "Todos":
                filtered_orch_df = filtered_orch_df[filtered_orch_df['system_type'] == selected_system_type]
            if selected_key_type != "Todos":
                filtered_orch_df = filtered_orch_df[filtered_orch_df['key_type'] == selected_key_type]
            if selected_priority_level != "Todos":
                filtered_orch_df = filtered_orch_df[filtered_orch_df['priority_level'] == selected_priority_level]

            # Display table with visual indicators
            display_cols_orch = [
                "session_id", "origin", "destination", "system_type", "priority_level",
                "key_type", "expires_at_str", "status", "symmetric_key_hex", "qkd_compatible_bits_len"
            ]
            
            # Add emojis for key_type and status
            def get_key_type_display(key_type):
                if key_type == "QKD": return "QKD"
                if key_type == "PQC": return "PQC"
                if key_type == "Fallback": return "Fallback"
                return key_type

            def get_status_display(status):
                if status == "active": return "Activa"
                if status == "revoked": return "Revocada"
                if status == "expired": return "Expirada"
                return status

            filtered_orch_df['key_type_display'] = filtered_orch_df['key_type'].apply(get_key_type_display)
            filtered_orch_df['status_display'] = filtered_orch_df['status'].apply(get_status_display)

            display_cols_orch_final = [
                "session_id", "origin", "destination", "system_type", "priority_level",
                "key_type_display", "expires_at_str", "status_display", "symmetric_key_hex", "qkd_compatible_bits_len"
            ]

            st.dataframe(filtered_orch_df[display_cols_orch_final], use_container_width=True)

            st.subheader("Acciones de Sesion")
            col_orch_action1, col_orch_action2, col_orch_action3 = st.columns(3)
            
            with col_orch_action1:
                new_origin = st.text_input("Origen para nueva sesion:", value="New-Origin", key="new_session_origin")
            with col_orch_action2:
                new_dest = st.text_input("Destino para nueva sesion:", value="New-Dest", key="new_session_dest")
            with col_orch_action3:
                new_system_type = st.selectbox("Tipo de Sistema (Nueva)", ["SCADA", "ERP", "API", "Banking", "QKD_Sim"], key="new_session_system_type")
                new_priority_level = st.selectbox("Prioridad (Nueva)", ["high", "medium", "low"], key="new_session_priority_level")

            if st.button("Asignar Nueva Sesion"):
                try:
                    result = orchestrator.assign_key_pair(new_origin, new_dest, new_system_type, new_priority_level)
                    st.success(f"Nueva sesion asignada: ID {result['session_id'][:8]}... con clave {result['key_type']}")
                    logger.info(f"New session assigned via UI: {result['session_id']}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error al asignar nueva sesion: {e}")
                    logger.error(f"Error assigning new session via UI: {e}", exc_info=True)

            st.markdown("---")
            st.subheader("Revocar Sesion Existente")
            session_ids_to_revoke = [""] + filtered_orch_df['session_id'].tolist()
            selected_session_to_revoke = st.selectbox("Selecciona Sesion a Revocar:", session_ids_to_revoke, key="revoke_session_select")
            if st.button("Revocar Sesion Seleccionada") and selected_session_to_revoke:
                try:
                    if orchestrator.revoke_session(selected_session_to_revoke):
                        st.success(f"Sesion {selected_session_to_revoke[:8]}... revocada con exito.")
                        logger.info(f"Session {selected_session_to_revoke} revoked via UI.")
                        st.rerun()
                    else:
                        st.warning(f"Sesion {selected_session_to_revoke[:8]}... no encontrada o ya inactiva.")
                except Exception as e:
                    st.error(f"Error al revocar sesion: {e}")
                    logger.error(f"Error revoking session {selected_session_to_revoke} via UI: {e}", exc_info=True)

            st.markdown("---")
            st.subheader("Reasignar Sesion (Regenerar Clave)")
            session_ids_to_reassign = [""] + filtered_orch_df[filtered_orch_df['status'] == 'active']['session_id'].tolist()
            selected_session_to_reassign = st.selectbox("Selecciona Sesion Activa para Reasignar:", session_ids_to_reassign, key="reassign_session_select")
            if st.button("Reasignar Sesion Seleccionada") and selected_session_to_reassign:
                try:
                    # Get current session details to re-use them for re-assignment
                    current_session_details = next((s for s in active_orchestrator_sessions if s['session_id'] == selected_session_to_reassign), None)
                    if current_session_details:
                        # Revoke old session
                        orchestrator.revoke_session(selected_session_to_reassign)
                        # Assign new session with same parameters
                        result = orchestrator.assign_key_pair(
                            current_session_details['origin'],
                            current_session_details['destination'],
                            current_session_details['system_type'],
                            current_session_details['priority_level']
                        )
                        st.success(f"Sesion {selected_session_to_reassign[:8]}... reasignada. Nueva ID: {result['session_id'][:8]}... con clave {result['key_type']}")
                        logger.info(f"Session {selected_session_to_reassign} re-assigned to {result['session_id']} via UI.")
                        st.rerun()
                    else:
                        st.warning(f"Sesion {selected_session_to_reassign[:8]}... no encontrada o no activa para reasignar.")
                except Exception as e:
                    st.error(f"Error al reasignar sesion: {e}")
                    logger.error(f"Error reassigning session {selected_session_to_reassign} via UI: {e}", exc_info=True)

        else:
            st.info("No hay sesiones activas en el orquestador aun. Asigna una nueva sesion para empezar.")


if __name__ == "__main__":
    logger.info("Q-LINK SIM iniciado con exito")
    main()

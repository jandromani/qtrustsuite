import paho.mqtt.client as mqtt
import time
import json
import logging
import os
import base64
import numpy as np

from q_link_sim.q_sync_bridge.orchestrator import get_orchestrator_instance
from q_link_sim.integration.crypto_bridge import encrypt_message_with_session, decrypt_message_with_session, CryptoBridgeError
from q_link_sim.q_ledger.audit import register_event

logger = logging.getLogger(__name__)

# MQTT Broker settings
MQTT_BROKER = os.getenv("MQTT_BROKER", "broker.hivemq.com")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_TOPIC_COMMAND = "qlinksim/scada/command"
MQTT_TOPIC_STATUS = "qlinksim/scada/status"

class SCADABridge:
    """
    Simulates a SCADA system bridge that communicates securely using keys
    managed by the Quantum Orchestrator.
    """
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.client = mqtt.Client(client_id=f"SCADA_Bridge_{device_id}")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.orchestrator = get_orchestrator_instance()
        self.active_session_id = None
        self.session_details = None # Stores key, key_type, etc.
        logger.info(f"SCADABridge for device '{self.device_id}' initialized.")

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info(f"SCADA Bridge '{self.device_id}' connected to MQTT Broker!")
            self.client.subscribe(MQTT_TOPIC_COMMAND)
            logger.info(f"Subscribed to topic: {MQTT_TOPIC_COMMAND}")
        else:
            logger.error(f"Failed to connect, return code {rc}\n")

    def _on_message(self, client, userdata, msg):
        logger.info(f"SCADA Bridge '{self.device_id}' received message on topic {msg.topic}")
        try:
            payload = json.loads(msg.payload.decode())
            command = payload.get("command")
            data = payload.get("data")
            sender_id = payload.get("sender_id", "Unknown")
            
            if command == "request_key_session":
                self._handle_key_session_request(sender_id, data)
            elif command == "send_encrypted_data":
                self._handle_encrypted_data(sender_id, data)
            else:
                logger.warning(f"Unknown command received: {command}")

        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON payload: {msg.payload}")
        except Exception as e:
            logger.error(f"Error processing MQTT message: {e}", exc_info=True)

    def _handle_key_session_request(self, sender_id: str, data: dict):
        """Handles a request to establish a key session."""
        system_type = data.get("system_type", "SCADA")
        priority_level = data.get("priority_level", "high")
        
        logger.info(f"'{self.device_id}' received key session request from '{sender_id}'. Assigning key...")
        try:
            # Request a key pair from the orchestrator
            orchestrator_response = self.orchestrator.assign_key_pair(
                origin=self.device_id,
                destination=sender_id,
                system_type=system_type,
                priority_level=priority_level
            )
            self.active_session_id = orchestrator_response["session_id"]
            self.session_details = orchestrator_response
            
            # Send confirmation back to sender (conceptually, in a real system this would be secure)
            response_payload = {
                "command": "key_session_established",
                "session_id": self.active_session_id,
                "key_type": self.session_details["key_type"],
                "message": f"Key session established with {self.device_id}. Session ID: {self.active_session_id[:8]}..."
            }
            self.client.publish(MQTT_TOPIC_STATUS, json.dumps(response_payload))
            logger.info(f"Key session {self.active_session_id[:8]}... established for '{self.device_id}'.")
            
            register_event(
                event_type="SCADA_KEY_ASSIGNED",
                session_id=self.active_session_id,
                origin_node=self.device_id,
                dest_node=sender_id,
                key_length_bits=len(self.session_details["key"]) * 8,
                event_metadata={"system_type": system_type, "priority_level": priority_level, "key_type": self.session_details["key_type"]}
            )

        except Exception as e:
            logger.error(f"Error assigning key session for '{self.device_id}': {e}", exc_info=True)
            error_payload = {
                "command": "key_session_failed",
                "sender_id": self.device_id,
                "error": str(e)
            }
            self.client.publish(MQTT_TOPIC_STATUS, json.dumps(error_payload))
            register_event(
                event_type="SCADA_KEY_ASSIGN_ERROR",
                session_id="N/A", # No session ID if assignment failed
                origin_node=self.device_id,
                dest_node=sender_id,
                event_metadata={"error_message": str(e), "request_data": data}
            )

    def _handle_encrypted_data(self, sender_id: str, data: dict):
        """Handles incoming encrypted data."""
        session_id = data.get("session_id")
        ciphertext = data.get("ciphertext")
        
        if not session_id or not ciphertext:
            logger.warning(f"Received incomplete encrypted data from '{sender_id}'.")
            return

        logger.info(f"'{self.device_id}' received encrypted data for session {session_id[:8]}...")
        
        # Validate session and decrypt
        validated_session = self.orchestrator.validate_session(session_id)
        if not validated_session:
            logger.warning(f"Session {session_id[:8]}... is invalid or expired. Cannot decrypt.")
            register_event(
                event_type="SCADA_DECRYPT_FAIL_SESSION_INVALID",
                session_id=session_id,
                origin_node=sender_id,
                dest_node=self.device_id,
                event_metadata={"ciphertext_len": len(ciphertext)}
            )
            return

        try:
            # Use the crypto bridge to decrypt
            decrypted_data = decrypt_message_with_session(session_id, ciphertext)
            logger.info(f"Data decrypted successfully for session {session_id[:8]}...: {decrypted_data}")
            
            register_event(
                event_type="SCADA_DATA_DECRYPTED",
                session_id=session_id,
                origin_node=sender_id,
                dest_node=self.device_id,
                message_content=decrypted_data,
                event_metadata={"ciphertext_len": len(ciphertext)}
            )

            # Simulate processing the decrypted data
            self.client.publish(MQTT_TOPIC_STATUS, json.dumps({
                "command": "data_processed",
                "session_id": session_id,
                "decrypted_data": decrypted_data,
                "receiver_id": self.device_id
            }))

        except CryptoBridgeError as e:
            logger.error(f"Decryption failed for session {session_id[:8]}...: {e}", exc_info=True)
            register_event(
                event_type="SCADA_DECRYPT_FAIL_CRYPTO",
                session_id=session_id,
                origin_node=sender_id,
                dest_node=self.device_id,
                event_metadata={"error": str(e), "ciphertext_len": len(ciphertext)}
            )
        except Exception as e:
            logger.error(f"Unexpected error during data handling for session {session_id[:8]}...: {e}", exc_info=True)
            register_event(
                event_type="SCADA_DECRYPT_FAIL_GENERIC",
                session_id=session_id,
                origin_node=sender_id,
                dest_node=self.device_id,
                event_metadata={"error": str(e), "ciphertext_len": len(ciphertext)}
            )

    def request_key_session(self, target_device_id: str, system_type: str = "SCADA", priority_level: str = "high"):
        """
        Sends a request to another SCADA device (or central system) to establish a key session.
        """
        payload = {
            "command": "request_key_session",
            "sender_id": self.device_id,
            "data": {
                "system_type": system_type,
                "priority_level": priority_level,
                "target_device_id": target_device_id
            }
        }
        self.client.publish(MQTT_TOPIC_COMMAND, json.dumps(payload))
        logger.info(f"'{self.device_id}' requested key session with '{target_device_id}'.")
        register_event(
            event_type="SCADA_KEY_REQUEST",
            session_id="N/A", # Session ID not yet assigned
            origin_node=self.device_id,
            dest_node=target_device_id,
            event_metadata={"system_type": system_type, "priority_level": priority_level}
        )

    def send_encrypted_data(self, target_device_id: str, plaintext_data: str):
        """
        Encrypts and sends data to a target SCADA device using the active session key.
        """
        if not self.active_session_id or not self.orchestrator.validate_session(self.active_session_id):
            logger.error(f"No active or valid session for '{self.device_id}'. Cannot send encrypted data.")
            register_event(
                event_type="SCADA_ENCRYPT_FAIL_NO_SESSION",
                session_id="N/A",
                origin_node=self.device_id,
                dest_node=target_device_id,
                message_content=plaintext_data,
                event_metadata={"error": "No active session"}
            )
            return

        logger.info(f"'{self.device_id}' encrypting data for session {self.active_session_id[:8]}...")
        try:
            ciphertext = encrypt_message_with_session(self.active_session_id, plaintext_data)
            
            payload = {
                "command": "send_encrypted_data",
                "sender_id": self.device_id,
                "session_id": self.active_session_id,
                "ciphertext": ciphertext
            }
            self.client.publish(MQTT_TOPIC_COMMAND, json.dumps(payload))
            logger.info(f"'{self.device_id}' sent encrypted data for session {self.active_session_id[:8]}... to '{target_device_id}'.")
            
            register_event(
                event_type="SCADA_DATA_ENCRYPTED",
                session_id=self.active_session_id,
                origin_node=self.device_id,
                dest_node=target_device_id,
                message_content=plaintext_data, # Hash of original message
                event_metadata={"ciphertext_len": len(ciphertext)}
            )

        except CryptoBridgeError as e:
            logger.error(f"Encryption failed for session {self.active_session_id[:8]}...: {e}", exc_info=True)
            register_event(
                event_type="SCADA_ENCRYPT_FAIL_CRYPTO",
                session_id=self.active_session_id,
                origin_node=self.device_id,
                dest_node=target_device_id,
                message_content=plaintext_data,
                event_metadata={"error": str(e)}
            )
        except Exception as e:
            logger.error(f"Unexpected error during data sending for session {self.active_session_id[:8]}...: {e}", exc_info=True)
            register_event(
                event_type="SCADA_ENCRYPT_FAIL_GENERIC",
                session_id=self.active_session_id,
                origin_node=self.device_id,
                dest_node=target_device_id,
                message_content=plaintext_data,
                event_metadata={"error": str(e)}
            )

    def run(self):
        """Connects to MQTT and starts the loop."""
        logger.info(f"SCADA Bridge '{self.device_id}' connecting to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}...")
        self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
        self.client.loop_start() # Start a non-blocking loop

        # Example usage: Request a key session and then send data
        # This part would be driven by actual SCADA logic
        # For demonstration, we'll just keep it running and listening

if __name__ == "__main__":
    # Configure logging for standalone execution
    from q_link_sim.logging_config import setup_logging
    LOG_FILE_PATH_SCADA = os.path.join(os.path.dirname(__file__), '..', 'data', 'logs', 'scada_bridge.log')
    setup_logging(log_file_path=LOG_FILE_PATH_SCADA, level=logging.INFO)

    # Initialize audit DB for standalone SCADA bridge
    LEDGER_DB_PATH_SCADA_STANDALONE = os.path.join(os.path.dirname(__file__), '..', 'data', 'q_ledger', 'ledger.db')
    initialize_audit_db(LEDGER_DB_PATH_SCADA_STANDALONE)

    # Create a SCADA bridge instance
    scada_device_id = "SCADA_Unit_001"
    scada_bridge = SCADABridge(device_id=scada_device_id)
    scada_bridge.run()

    logger.info(f"SCADA Bridge '{scada_device_id}' is running. Press Ctrl+C to exit.")

    try:
        # Example: Request a key session after a delay
        time.sleep(5) # Give time for MQTT connection
        target_device = "Central_Control"
        scada_bridge.request_key_session(target_device)
        
        time.sleep(10) # Wait for session to be potentially established
        scada_bridge.send_encrypted_data(target_device, "Sensor reading: Temperature 25.5C, Pressure 1.2 bar.")

        while True:
            time.sleep(1) # Keep the main thread alive
    except KeyboardInterrupt:
        logger.info(f"SCADA Bridge '{scada_device_id}' stopped.")
        scada_bridge.client.loop_stop()
        scada_bridge.client.disconnect()

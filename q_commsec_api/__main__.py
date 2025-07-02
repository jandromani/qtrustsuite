# q_commsec_api/__main__.py
import os, uvicorn

if __name__ == "__main__":
    port = int(os.getenv("QCSEC_PORT", "5000"))

    # pasamos la app como import-string  ➜  NO hay warning
    uvicorn.run(
        "q_commsec_api.main:app",      # <- paquete.modulo:objeto
        host="127.0.0.1",
        port=port,
        reload=False                  # quita reload si no lo necesitas
    )

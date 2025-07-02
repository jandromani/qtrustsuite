@echo off
:: Cambiar a la codificación UTF-8
chcp 65001

:: Q-TRUST local stack (Hardhat + Orchestrator + API + Streamlit)

:: Explicación técnica para el usuario
echo.
echo ***************************************************************
echo.
echo          ** Q-TRUST: Quantum Communications and Trust Network **
echo.
echo ***************************************************************
echo.
echo Bienvenido al sistema Q-TRUST. Esta aplicación utiliza
echo tecnologías avanzadas de **criptografía cuántica** para
echo generar claves de seguridad y distribuirlas de forma segura
echo entre diferentes nodos en una red. El sistema simula el uso
echo de **Distribución Cuántica de Claves (QKD)** y **Criptografía
echo Post-Cuántica (PQC)** para garantizar comunicaciones seguras,
echo incluso frente a ataques futuros de computadoras cuánticas.
echo.
echo Este proyecto tiene aplicaciones en ciberseguridad avanzada,
echo protección de datos sensibles y redes de comunicación ultra-seguras.
echo.
echo ***************************************************************
echo.
echo ** ¿Cómo funciona? **

echo.
echo - Utilizamos protocolos cuánticos como BB84 para generar claves
echo   seguras entre nodos, garantizando que nadie pueda interceptar
echo   las claves sin ser detectado.
echo - Además, integramos soluciones Post-Cuánticas para resistir
echo   los ataques de futuras computadoras cuánticas que podrían
echo   romper los métodos de cifrado actuales.
echo - Todo esto está registrado en un **Blockchain** para garantizar
echo   la transparencia y la seguridad a largo plazo.
echo.
echo ***************************************************************
echo.

:: Explicación para niños o público general
echo Ahora imagina que estas usando una **caja fuerte** para guardar tus
echo secretos (tus datos). Para abrir esta caja fuerte, necesitas una
echo **llave** especial que nadie más pueda conseguir. La llave que usas
echo para abrir tu caja está **protegida por una tecnología muy avanzada**,
echo tan avanzada que ni siquiera las computadoras más poderosas pueden
echo hackearla.
echo.
echo Con Q-TRUST, estamos construyendo **un sistema de cajas fuertes** que
echo **ningún hacker podrá abrir** porque las llaves de las cajas están
echo basadas en **física cuántica**, lo que las hace **imposibles de copiar**.
echo Esto lo usamos en áreas donde la **seguridad es clave**, como en
echo **bancos**, **gobiernos** o **infraestructuras críticas**.
echo.
echo ***************************************************************
echo.
echo ** Ejemplo en la vida real **:
echo Imagina que un banco quiere asegurarse de que nadie pueda robar el
echo dinero de sus clientes. Utilizan **Q-TRUST** para garantizar que
echo solo las personas correctas (como tú) puedan acceder a tu dinero,
echo usando claves **ultra-seguras** que no se pueden hackear.
echo.
echo ***************************************************************
echo.

:: Solicitar confirmación al usuario para continuar
echo.
echo ****************************************************************
echo **  Para continuar con la ejecución de Q-TRUST, por favor presiona **
echo **  "Y" para confirmar que has leído la información anterior y    **
echo **  entiendes que esta es una plataforma que utiliza tecnología **
echo **  cuántica avanzada para comunicaciones seguras.              **
echo ****************************************************************
echo.

set /p user_input=Press Y to continue:

if /i "%user_input%" NEQ "Y" (
    echo.
    echo You need to read the information and press "Y" to continue.
    exit /b
)

:: Continuar con la ejecución de los componentes después de la confirmación
set "PROJECT_ROOT=C:\Users\abaratas\Downloads\q-commsec-api-project"
set "CONDA_ENV=qtrust"

:: 1) Iniciar Hardhat Node ──────────────────────────
start "HARDHAT NODE" cmd /k ^
    "cd /d %PROJECT_ROOT% && npm run hardhat:node"

:: Espera 10 segundos para asegurar que Hardhat esté corriendo
timeout /t 2 /nobreak

:: 2) Iniciar Orchestrator ──────────────────────────
start "ORCHESTRATOR" cmd /k ^
    "cd /d %PROJECT_ROOT% && conda activate %CONDA_ENV% && python -m q_link_sim.q_sync_bridge.orchestrator"

:: Espera 10 segundos para asegurar que Orchestrator esté listo
timeout /t 2 /nobreak

:: 3) Iniciar la API de Q-COMMSEC ────────────────────
start "API" cmd /k ^
    "cd /d %PROJECT_ROOT% && conda activate %CONDA_ENV% && uvicorn q_commsec_api.main:app --host 127.0.0.1 --port 5000 --reload"

:: Espera 10 segundos para asegurar que la API esté funcionando
timeout /t 5 /nobreak

:: 4) Iniciar Streamlit App ──────────────────────────
start "STREAMLIT" cmd /k ^
    "cd /d %PROJECT_ROOT% && conda activate %CONDA_ENV% && streamlit run q_link_sim/app.py"

exit /b

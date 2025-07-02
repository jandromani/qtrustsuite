import importlib, platform
pkgs = ["streamlit","numpy","pandas","networkx","matplotlib",
        "plotly","sqlalchemy","web3","eth_account","jsonpickle"]

print("Python", platform.python_version(), "\n" + "-"*35)
for p in pkgs:
    try:
        mod = importlib.import_module(p.replace(".", "_"))
        print(f"✓ {p:<12} {mod.__version__}")
    except Exception as e:
        print(f"✗ {p:<12} {e}")

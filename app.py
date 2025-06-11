# ========================================
# app.py - SISTEMA HÍBRIDO PARA RAILWAY
# ========================================

import streamlit as st
import os
import sys
from pathlib import Path

# Configurar paths
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def main():
    """Función principal - Sin set_page_config para evitar conflictos"""
    
    try:
        # Importar y ejecutar launcher híbrido
        from app_launcher import main as launcher_main
        launcher_main()
    
    except ImportError as e:
        st.error(f"❌ Error de importación: {str(e)}")
        st.info("Verifica que app_launcher.py esté presente")
    
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
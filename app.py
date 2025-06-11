# ========================================
# app.py - PUNTO DE ENTRADA PARA RAILWAY
# Sistema Híbrido
# ========================================

import streamlit as st
import os
import sys
from pathlib import Path

# Configurar página
st.set_page_config(
    page_title="🔀 Sistema Híbrido - Telmex",
    page_icon="🔀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configurar paths
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Detectar ambiente
IS_RAILWAY = os.getenv('RAILWAY_ENVIRONMENT') is not None

def main():
    """Función principal específica para Sistema Híbrido"""
    
    try:
        # Mostrar información del sistema
        with st.sidebar:
            st.success("🔀 **Sistema Híbrido**")
            st.caption("Sistema unificado con detección automática")
            if IS_RAILWAY:
                st.success("🚂 Railway Production")
            else:
                st.info("🏠 Desarrollo Local")
        
        # Importar y ejecutar launcher híbrido
        from app_launcher import main as launcher_main
        launcher_main()
    
    except ImportError as e:
        st.error(f"""
        ❌ **Error de importación:** {str(e)}
        
        Verifica que todos los archivos estén presentes en Railway.
        """)
    
    except Exception as e:
        st.error(f"""
        ❌ **Error:** {str(e)}
        
        **Información del ambiente:**
        - Railway: {IS_RAILWAY}
        - Directorio: {os.getcwd()}
        """)

if __name__ == "__main__":
    main()

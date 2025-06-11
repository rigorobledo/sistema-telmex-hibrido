"""
Launcher Unificado - Sistema de Normalización Telmex
==================================================

Permite elegir entre:
- Sistema Original (Síncrono)
- Sistema Asíncrono
- Sistema Híbrido (Ambos)
"""

import streamlit as st
import sys
import os


# Configurar página
st.set_page_config(
    page_title="🚀 Sistema Unificado - Normalización Telmex",
    page_icon="🚀",
    layout="wide",
    initial_sidebar_state="expanded"
)

def show_launcher():
    """Mostrar pantalla de selección de sistema"""
    
    # Header principal
    col_logo, col_title = st.columns([1, 8])

    
    
    with col_logo:
        try:
            st.image("logo_RN.png", width=120)
        except:
            st.markdown("🏠")
    
    with col_title:
        st.markdown("""
        <div style="text-align: left;">
            <h2>🚀 Red Nacional Última Milla</h2>
            <h4>Sistema Integral de Normalización - Launcher Unificado</h4>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Selector de sistema
    st.markdown("## 🎯 Selecciona el Sistema a Usar")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### ⚡ Sistema Original (Síncrono)
        
        **Características:**
        - ✅ Procesamiento inmediato
        - ✅ Familiar y estable
        - ✅ Resultados al instante
        - ✅ Para archivos pequeños/medianos
        
        **Ideal para:**
        - Archivos < 5,000 registros
        - Tareas urgentes
        - Validaciones rápidas
        """)
        
        if st.button("⚡ USAR SISTEMA ORIGINAL", type="primary", use_container_width=True):
            # LIMPIAR COMPLETAMENTE Y FORZAR RECARGA
            st.session_state.clear()
            st.session_state.selected_mode = 'original'
            st.session_state.force_reload = True
            st.rerun()

    with col2:
        st.markdown("""
        ### 🔄 Sistema Asíncrono
        
        **Características:**
        - ✅ Procesamiento en background
        - ✅ Progreso en tiempo real
        - ✅ No bloquea la interfaz
        - ✅ Para archivos grandes
        
        **Ideal para:**
        - Archivos > 5,000 registros
        - Múltiples archivos
        - Procesamiento masivo
        """)
        
        if st.button("🔄 USAR SISTEMA ASÍNCRONO", type="secondary", use_container_width=True):
            # LIMPIAR COMPLETAMENTE Y FORZAR RECARGA
            st.session_state.clear()
            st.session_state.selected_mode = 'async'
            st.session_state.force_reload = True
            st.rerun()

    with col3:
        st.markdown("""
        ### 🔀 Sistema Híbrido
        
        **Características:**
        - ✅ Ambos sistemas integrados
        - ✅ Selección automática
        - ✅ Máxima flexibilidad
        - ✅ Interfaz unificada
        
        **Ideal para:**
        - Uso diario completo
        - Diferentes tipos de archivos
        - Máximo rendimiento
        """)
        
        if st.button("🔀 USAR SISTEMA HÍBRIDO", type="primary", use_container_width=True):
            # LIMPIAR COMPLETAMENTE Y FORZAR RECARGA
            st.session_state.clear()
            st.session_state.selected_mode = 'hybrid'
            st.session_state.force_reload = True
            st.rerun()

            
    
    # Información adicional
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📊 Comparación de Sistemas")
        
        comparison_data = {
            'Característica': [
                'Velocidad inicio',
                'Archivos grandes', 
                'Múltiples archivos',
                'Progreso tiempo real',
                'Uso de recursos',
                'Complejidad'
            ],
            'Original': [
                '⚡ Inmediato',
                '❌ Lento',
                '❌ Uno por vez',
                '❌ No',
                '🟡 Medio',
                '✅ Simple'
            ],
            'Asíncrono': [
                '🟡 Setup inicial',
                '✅ Excelente',
                '✅ Múltiples',
                '✅ Sí',
                '🟢 Eficiente',
                '🟡 Intermedio'
            ],
            'Híbrido': [
                '🟡 Setup inicial',
                '✅ Excelente',
                '✅ Múltiples',
                '✅ Sí',
                '🟢 Eficiente',
                '🟡 Intermedio'
            ]
        }
        
        import pandas as pd
        df_comparison = pd.DataFrame(comparison_data)
        st.dataframe(df_comparison, use_container_width=True, hide_index=True)
    
    with col2:
        st.markdown("### ⚙️ Configuración Actual")
        
        from async_processor.config import AsyncConfig
        from async_processor.utils import AsyncUtils
        
        env = AsyncUtils.detect_environment()
        
        st.info(f"""
        **🔧 Ambiente:** {env['environment_name']}
        **🎯 Umbral asíncrono:** {AsyncConfig.AUTO_ASYNC_THRESHOLD:,} registros
        **👥 Workers máximos:** {AsyncConfig.MAX_WORKERS}
        **⏱️ Timeout:** {AsyncConfig.TASK_TIMEOUT_MINUTES} minutos
        """)
        
        if st.button("⚙️ Cambiar Configuración"):
            st.info("💡 Para cambiar configuración, edita `async_processor/config.py`")

    # Limpiar cualquier contenido previo de sistemas
    if st.session_state.get('selected_mode') is None:
        # Asegurar que no hay contenido residual
        st.empty()
        
        # Aplicar CSS para evitar problemas de layout
        st.markdown("""
        <style>
        .main .block-container {
            padding-top: 1rem;
            padding-bottom: 1rem;
            max-width: 100%;
        }
        
        .stTabs > div > div > div > div {
            padding-top: 1rem;
        }
        
        /* Asegurar que los sistemas usen todo el espacio */
        .system-container {
            width: 100%;
            min-height: 80vh;
            padding: 1rem;
        }
        </style>
        """, unsafe_allow_html=True)

def launch_original_system():
    """Lanzar sistema original"""
        
    # Aplicar CSS para usar todo el espacio disponible
    st.markdown("""
    <style>
    .main .block-container {
        padding-top: 0rem;
        padding-bottom: 0rem;
        max-width: 100%;
        width: 100%;
    }
    
    .system-hybrid {
        width: 100%;
        min-height: 100vh;
    }
    </style>
    """, unsafe_allow_html=True)
    
    
    st.success("🚀 Cargando Sistema Original...")
    
    # Marcar que se seleccionó sistema original
    st.session_state.selected_mode = 'original'
    
    try:
        # Importar y ejecutar el sistema original
        from sistema_completo_normalizacion import main_con_autenticacion
        
        # Botón para volver al launcher ANTES del sistema
        if st.button("⬅️ Volver al Launcher"):
            # LIMPIAR SESSION STATE COMPLETAMENTE
            st.session_state.selected_mode = None
            st.session_state.usuario_autenticado = False
            if 'usuario_actual' in st.session_state:
                del st.session_state.usuario_actual
            if 'token_sesion' in st.session_state:
                del st.session_state.token_sesion
            
            st.success("🔄 Regresando al Launcher...")
            st.rerun()
        
        # Ejecutar el sistema original completo
        main_con_autenticacion()
        
    except Exception as e:
        st.error(f"❌ Error cargando sistema original: {str(e)}")
        
        # Botón para volver al launcher
        if st.button("⬅️ Volver al Launcher"):
            # LIMPIAR SESSION STATE
            st.session_state.selected_mode = None
            st.session_state.usuario_autenticado = False
            if 'usuario_actual' in st.session_state:
                del st.session_state.usuario_actual
            if 'token_sesion' in st.session_state:
                del st.session_state.token_sesion
            st.rerun()

def launch_async_system():

    """Lanzar sistema híbrido"""
    
    # Aplicar CSS para usar todo el espacio disponible
    st.markdown("""
    <style>
    .main .block-container {
        padding-top: 0rem;
        padding-bottom: 0rem;
        max-width: 100%;
        width: 100%;
    }
    
    .system-hybrid {
        width: 100%;
        min-height: 100vh;
    }
    </style>
    """, unsafe_allow_html=True)
    
 
    """Lanzar sistema asíncrono"""
    st.success("🚀 Cargando Sistema Asíncrono...")
    
    # Marcar que se seleccionó sistema asíncrono
    st.session_state.selected_mode = 'async'
    
    try:
        # Importar y ejecutar el sistema asíncrono
        from async_processor.dashboard import show_unified_dashboard
        from sistema_completo_normalizacion import inicializar_sistema_usuarios, verificar_autenticacion, mostrar_pantalla_login, mostrar_barra_usuario
        
        # Inicializar sistema de usuarios (mismo que sistema original)
        inicializar_sistema_usuarios()
        
        # Verificar autenticación
        if not verificar_autenticacion():
            st.markdown("## 🔐 Acceso al Sistema Asíncrono")
            mostrar_pantalla_login()
            return
        
        # Usuario autenticado - mostrar barra de usuario
        mostrar_barra_usuario()
        
        # Botón para volver al launcher
        if st.button("⬅️ Volver al Launcher"):
            # LIMPIAR SESSION STATE COMPLETAMENTE
            st.session_state.selected_mode = None
            st.session_state.usuario_autenticado = False
            if 'usuario_actual' in st.session_state:
                del st.session_state.usuario_actual
            if 'token_sesion' in st.session_state:
                del st.session_state.token_sesion
            
            st.success("🔄 Regresando al Launcher...")
            st.rerun()
        
        # Mostrar sistema asíncrono
        show_unified_dashboard()
        
    except Exception as e:
        st.error(f"❌ Error cargando sistema asíncrono: {str(e)}")
        
        # Botón para volver al launcher (fallback)
        if st.button("⬅️ Volver al Launcher"):
            # LIMPIAR SESSION STATE
            st.session_state.selected_mode = None
            st.session_state.usuario_autenticado = False
            if 'usuario_actual' in st.session_state:
                del st.session_state.usuario_actual
            if 'token_sesion' in st.session_state:
                del st.session_state.token_sesion
            st.rerun()

def launch_hybrid_system():
    """Lanzar sistema híbrido con resultados integrados"""
    
    # Aplicar CSS para usar todo el espacio disponible
    st.markdown("""
    <style>
    .main .block-container {
        padding-top: 0rem;
        padding-bottom: 0rem;
        max-width: 100%;
        width: 100%;
    }
    
    .system-hybrid {
        width: 100%;
        min-height: 100vh;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.success("🚀 Cargando Sistema Híbrido...")
    
    # Marcar que se seleccionó sistema híbrido
    st.session_state.selected_mode = 'hybrid'
    
    try:
        # Importar funciones del sistema original
        from sistema_completo_normalizacion import (
            inicializar_sistema_usuarios, 
            verificar_autenticacion, 
            mostrar_pantalla_login, 
            mostrar_barra_usuario,
            mostrar_dashboard_principal,
            mostrar_configuracion_sistema
        )
        from async_processor.dashboard import show_unified_dashboard, UnifiedDashboard
        
        # PASO 1: Inicializar sistema de usuarios
        inicializar_sistema_usuarios()
        
        # PASO 2: Verificar autenticación OBLIGATORIA
        if not verificar_autenticacion():
            st.markdown("## 🔐 Acceso al Sistema Híbrido")
            st.info("Debes autenticarte para usar el sistema híbrido")
            mostrar_pantalla_login()
            return  # IMPORTANTE: Salir aquí si no está autenticado
        
        # PASO 3: Usuario autenticado - mostrar barra de usuario
        mostrar_barra_usuario()
        
        # PASO 4: Botón para volver al launcher (ANTES del contenido)
        col1, col2 = st.columns([1, 8])
        with col1:
            if st.button("⬅️ Launcher"):
                # LIMPIAR SESSION STATE COMPLETAMENTE
                st.session_state.selected_mode = None
                st.session_state.usuario_autenticado = False
                if 'usuario_actual' in st.session_state:
                    del st.session_state.usuario_actual
                if 'token_sesion' in st.session_state:
                    del st.session_state.token_sesion
                
                st.success("🔄 Regresando al Launcher...")
                st.rerun()
        with col2:
            st.markdown("## 🔀 Sistema Híbrido - Procesamiento Inteligente")
        
        # PASO 5: Verificar gestión de usuarios
        if st.session_state.get('mostrar_gestion_usuarios', False):
            from sistema_completo_normalizacion import mostrar_gestion_usuarios
            mostrar_gestion_usuarios()
            
            if st.button("⬅️ Volver al Dashboard Híbrido"):
                st.session_state.mostrar_gestion_usuarios = False
                st.rerun()
            return
        
        # PASO 6: Mostrar interfaz híbrida con tabs MEJORADOS
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "📊 Dashboard", 
            "📁 Carga Inteligente", 
            "🔄 Monitoreo Asíncrono", 
            "📋 Ver Resultados",  # ← NUEVA PESTAÑA PRINCIPAL
            "📊 Análisis Completo",  # ← PESTAÑA MEJORADA
            "⚙️ Configuración"
        ])
        
        with tab1:
            # Dashboard principal con métricas generales
            mostrar_dashboard_principal()

        with tab2:
            # Carga inteligente con detección automática
            st.info("🧠 El sistema detecta automáticamente si usar modo síncrono o asíncrono")
            show_unified_dashboard()

        with tab3:
            # Monitoreo específico de tareas asíncronas
            mostrar_monitoreo_asincrono_hibrido()

        with tab4:
            # ← NUEVA PESTAÑA: Resultados unificados
            mostrar_resultados_sistema_hibrido()

        with tab5:
            # ← PESTAÑA MEJORADA: Análisis completo (antes "Resultados")
            mostrar_analisis_completo_hibrido()

        with tab6:
            # Configuración del sistema
            mostrar_configuracion_sistema()
        
    except Exception as e:
        st.error(f"❌ Error cargando sistema híbrido: {str(e)}")
        
        # Mostrar detalles del error para debugging
        with st.expander("🔧 Detalles del error"):
            import traceback
            st.code(traceback.format_exc())
        
        # Botón para volver al launcher
        if st.button("⬅️ Volver al Launcher"):
            # LIMPIAR SESSION STATE COMPLETAMENTE
            st.session_state.clear()
            st.success("🔄 Regresando al Launcher...")
            st.rerun()

def main():
    """Función principal del launcher"""
    
    # VERIFICAR SI VIENE DE UN BOTÓN (página limpia)
    if st.session_state.get('force_reload', False):
        st.session_state.force_reload = False
        
        # Forzar renderizado limpio
        st.empty()
        
        # Renderizar sistema seleccionado en página LIMPIA
        mode = st.session_state.get('selected_mode')
        
        if mode == 'original':
            render_original_system_clean()
        elif mode == 'async':
            render_async_system_clean()
        elif mode == 'hybrid':
            render_hybrid_system_clean()
        else:
            show_launcher()
        return
    
    # DETECTAR LOGOUT
    if st.session_state.get('logout_completed', False):
        st.session_state.logout_completed = False
        st.session_state.selected_mode = None
        st.success("👋 Sesión cerrada exitosamente")
        st.info("🚀 Bienvenido de nuevo al Launcher")
        show_launcher()
        return
    
    # MOSTRAR LAUNCHER POR DEFECTO
    if not st.session_state.get('selected_mode'):
        show_launcher()
    else:
        # Si hay modo seleccionado, renderizar
        mode = st.session_state.selected_mode
        if mode == 'original':
            render_original_system_clean()
        elif mode == 'async':
            render_async_system_clean()
        elif mode == 'hybrid':
            render_hybrid_system_clean()
        else:
            show_launcher()


def render_original_system_clean():
    """Renderizar sistema original en página limpia"""
    
    # CSS para página completa
    st.markdown("""
    <style>
    .main .block-container {
        padding-top: 1rem;
        max-width: 100%;
        width: 100%;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Botón de regreso al launcher
    if st.button("⬅️ Volver al Launcher", key="back_to_launcher_original"):
        st.session_state.clear()
        st.rerun()
    
    st.markdown("---")
    
    try:
        from sistema_completo_normalizacion import main_con_autenticacion
        main_con_autenticacion()
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")

def render_async_system_clean():
    """Renderizar sistema asíncrono en página limpia"""
    
    # CSS para página completa
    st.markdown("""
    <style>
    .main .block-container {
        padding-top: 1rem;
        max-width: 100%;
        width: 100%;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Botón de regreso al launcher
    if st.button("⬅️ Volver al Launcher", key="back_to_launcher_async"):
        st.session_state.clear()
        st.rerun()
    
    st.markdown("---")
    
    try:
        from async_processor.dashboard import show_unified_dashboard
        from sistema_completo_normalizacion import inicializar_sistema_usuarios, verificar_autenticacion, mostrar_pantalla_login, mostrar_barra_usuario
        
        inicializar_sistema_usuarios()
        
        if not verificar_autenticacion():
            st.markdown("## 🔐 Acceso al Sistema Asíncrono")
            mostrar_pantalla_login()
            return
        
        mostrar_barra_usuario()
        show_unified_dashboard()
        
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")

def render_hybrid_system_clean():
    """Renderizar sistema híbrido en página limpia"""
    
    # CSS para página completa
    st.markdown("""
    <style>
    .main .block-container {
        padding-top: 1rem;
        max-width: 100%;
        width: 100%;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Botón de regreso al launcher
    if st.button("⬅️ Volver al Launcher", key="back_to_launcher_hybrid"):
        st.session_state.clear()
        st.rerun()
    
    st.markdown("---")
    
    try:
        # Tu código de sistema híbrido aquí
        from sistema_completo_normalizacion import (
            inicializar_sistema_usuarios, verificar_autenticacion, 
            mostrar_pantalla_login, mostrar_barra_usuario,
            mostrar_dashboard_principal, mostrar_seccion_resultados,
            mostrar_configuracion_sistema
        )
        from async_processor.dashboard import show_unified_dashboard
        
        inicializar_sistema_usuarios()
        
        if not verificar_autenticacion():
            st.markdown("## 🔐 Acceso al Sistema Híbrido")
            mostrar_pantalla_login()
            return
        
        mostrar_barra_usuario()
        st.markdown("## 🔀 Sistema Híbrido - Procesamiento Inteligente")
        
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Dashboard", "📁 Carga Inteligente", "🔄 Monitoreo Asíncrono", 
            "📋 Resultados", "⚙️ Configuración"
        ])
        
        with tab1:
            mostrar_dashboard_principal()
        with tab2:
            show_unified_dashboard()
        with tab3:
            st.info("📊 Usa la pestaña 'Carga Inteligente' para monitoreo")
        with tab4:
            mostrar_seccion_resultados()
        with tab5:
            mostrar_configuracion_sistema()
        
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")



def mostrar_monitoreo_asincrono_hibrido():
    """Monitoreo específico para el sistema híbrido"""
    
    st.markdown("### 🔄 Monitoreo de Tareas Asíncronas")
    
    try:
        from async_processor.core import AsyncProcessor
        if 'async_processor' in st.session_state:
            processor = st.session_state.async_processor
            stats = processor.get_system_stats()
            
            # Métricas principales
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("🔄 Workers Activos", f"{stats['workers_active']}/{stats['workers_max']}")
            with col2:
                st.metric("📋 Tareas Pendientes", stats['total_pending'])
            with col3:
                st.metric("✅ Completadas", stats['stats']['total_processed'])
            with col4:
                st.metric("❌ Fallidas", stats['stats']['total_failed'])
            
            # Estado por prioridad
            if stats['total_pending'] > 0:
                st.markdown("#### 📊 Colas por Prioridad")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric(
                        "🔴 Alta (SUPERUSUARIO)", 
                        stats['pending_by_priority']['high'],
                        help="Tareas de usuarios con rol SUPERUSUARIO"
                    )
                
                with col2:
                    st.metric(
                        "🟡 Media (GERENTE)", 
                        stats['pending_by_priority']['normal'],
                        help="Tareas de usuarios con rol GERENTE"
                    )
                
                with col3:
                    st.metric(
                        "🟢 Normal (USUARIO)", 
                        stats['pending_by_priority']['low'],
                        help="Tareas de usuarios con rol USUARIO"
                    )
            else:
                st.success("✅ No hay tareas pendientes en este momento")
            
            # Botones de acción
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🔄 Actualizar Estado"):
                    st.rerun()
            
            with col2:
                if st.button("📋 Ver Mis Tareas Detalladas"):
                    # Cambiar a vista detallada de tareas
                    st.session_state.show_detailed_tasks = True
                    st.rerun()
            
            # Auto-refresh si hay tareas pendientes
            if stats['total_pending'] > 0:
                st.info("🔄 Actualizando automáticamente cada 10 segundos...")
                time.sleep(10)
                st.rerun()
        else:
            st.warning("⚠️ Sistema asíncrono no inicializado")
            if st.button("🚀 Inicializar Sistema Asíncrono"):
                from async_processor.core import AsyncProcessor
                st.session_state.async_processor = AsyncProcessor()
                st.session_state.async_processor.start_workers()
                st.rerun()
    except Exception as e:
        st.error(f"❌ Error al cargar monitoreo asíncrono: {str(e)}")
        
        # Mostrar detalles del error para debugging
        with st.expander("🔧 Detalles del error"):
            import traceback
            st.code(traceback.format_exc())
        
        # Botón para volver al launcher
        if st.button("⬅️ Volver al Launcher"):
            # LIMPIAR SESSION STATE COMPLETAMENTE
            st.session_state.clear()
            st.success("🔄 Regresando al Launcher...")
            st.rerun()


if __name__ == "__main__":
    main()
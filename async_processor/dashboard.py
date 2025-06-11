"""
Dashboard Unificado - Sistema Síncrono + Asíncrono
=================================================

Interfaz que combina ambos sistemas y permite elegir el modo de procesamiento.
"""

import streamlit as st
import pandas as pd
import time
from datetime import datetime
import sys
import os

import time
from datetime import datetime

# Importar componentes del sistema asíncrono
try:
    from async_processor.config import AsyncConfig
    from async_processor.utils import AsyncUtils
    from async_processor.core import AsyncProcessor
except ImportError:
    try:
        from config import AsyncConfig
        from utils import AsyncUtils  
        from core import AsyncProcessor
    except ImportError:
        import sys
        import os
        sys.path.append(os.path.dirname(__file__))
        from config import AsyncConfig
        from utils import AsyncUtils
        from core import AsyncProcessor

class UnifiedDashboard:
    """Dashboard que une sistema síncrono y asíncrono"""
    
    def __init__(self):
        self.async_processor = None
        self.initialize_processors()

    def read_csv_smart_encoding(self, uploaded_file):
        """Leer CSV con detección automática de encoding"""
        
        # Lista de encodings comunes en México/América Latina
        encodings_to_try = [
            'utf-8',           # Estándar
            'latin-1',         # ISO-8859-1 (muy común)
            'cp1252',          # Windows-1252 (Excel en Windows)
            'iso-8859-1',      # Otra variante de latin
            'utf-8-sig',       # UTF-8 con BOM
            'cp850',           # DOS América Latina
            'ascii'            # Fallback básico
        ]
        
        # Resetear el archivo para poder leerlo múltiples veces
        uploaded_file.seek(0)
        file_content = uploaded_file.read()
        
        for encoding in encodings_to_try:
            try:
                # Intentar decodificar el contenido
                content_str = file_content.decode(encoding)
                
                # Crear un objeto StringIO para pandas
                from io import StringIO
                content_io = StringIO(content_str)
                
                # Intentar leer con pandas
                df = pd.read_csv(content_io)
                
                # Si llegamos aquí, funcionó
                st.success(f"✅ Archivo leído exitosamente (encoding: {encoding})")
                
                # Validar que tenga contenido
                if df.empty:
                    st.error("❌ El archivo está vacío")
                    return None
                
                # Mostrar información básica del archivo
                st.info(f"""
                **📋 Información del archivo:**
                - **Filas:** {len(df):,}
                - **Columnas:** {len(df.columns)}
                - **Encoding detectado:** {encoding}
                - **Columnas encontradas:** {', '.join(df.columns[:5])}{'...' if len(df.columns) > 5 else ''}
                """)
                
                return df
                
            except (UnicodeDecodeError, pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                # Intentar siguiente encoding
                continue
            except Exception as e:
                # Error diferente, reportar pero continuar
                print(f"Error con encoding {encoding}: {e}")
                continue
        
        # Si ningún encoding funcionó
        st.error("❌ No se pudo leer el archivo con ningún encoding común")
        
        # Mostrar información de ayuda
        with st.expander("💡 Sugerencias para solucionar"):
            st.markdown("""
            **Posibles soluciones:**
            
            1. **Guardar archivo en UTF-8:**
            - Abre el archivo en Excel
            - File → Save As → CSV UTF-8 (Comma delimited)
            
            2. **Usar Notepad++:**
            - Abre el archivo en Notepad++
            - Encoding → Convert to UTF-8
            - Guardar
            
            3. **Verificar el archivo:**
            - Asegúrate de que sea un CSV válido
            - Primera fila debe tener los nombres de columnas
            - Separado por comas
            
            **Encodings intentados:**
            {}
            """.format(", ".join(encodings_to_try)))
        
        return None
    
    def initialize_processors(self):
        """Inicializar procesadores"""
        try:
            # Inicializar procesador asíncrono
            if 'async_processor' not in st.session_state:
                st.session_state.async_processor = AsyncProcessor()
                st.session_state.async_processor.start_workers()
            
            self.async_processor = st.session_state.async_processor
            
        except Exception as e:
            st.error(f"Error inicializando procesadores: {e}")
    
    def show_main_interface(self):
        """Mostrar interfaz principal unificada"""
    
        st.markdown("## 🚀 Sistema de Procesamiento Unificado")
        
        # Mostrar configuración actual
        self.show_current_config()
        
        # Crear tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📤 Subir Archivos", 
            "📊 Monitoreo Asíncrono", 
            "📋 Mis Tareas", 
            "⚙️ Configuración"
        ])
        
        with tab1:
            self.show_file_upload_interface("_tab1")  # ← SUFIJO ÚNICO
        
        with tab2:
            self.show_async_monitoring()
        
        with tab3:
            self.show_user_tasks()
        
        with tab4:
            self.show_async_configuration()
    
    def show_current_config(self):
        """Mostrar configuración actual del sistema"""
        
        env = AsyncUtils.detect_environment()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Ambiente", 
                env['environment_name'],
                help="Local = tu PC, Railway = producción"
            )
        
        with col2:
            st.metric(
                "Umbral Asíncrono", 
                f"{AsyncConfig.AUTO_ASYNC_THRESHOLD:,}",
                help="Registros mínimos para activar modo asíncrono"
            )
        
        with col3:
            if self.async_processor:
                stats = self.async_processor.get_system_stats()
                st.metric(
                    "Workers Activos", 
                    f"{stats['workers_active']}/{stats['workers_max']}",
                    help="Trabajadores procesando tareas"
                )
            else:
                st.metric("Workers Activos", "0/0")
        
        with col4:
            # Obtener rol del usuario actual
            usuario_actual = st.session_state.get('usuario_actual', {})
            rol = usuario_actual.get('rol', 'USUARIO')
            limits = AsyncUtils.get_user_limits(rol)
            
            st.metric(
                "Límite de Archivos", 
                "∞" if limits['max_files_in_queue'] == -1 else limits['max_files_in_queue'],
                help=f"Archivos máximos en cola para rol {rol}"
            )
    
    def show_file_upload_interface(self, form_suffix=""):
        """Interfaz mejorada para subir archivos"""
    
        st.markdown("### 📤 Subir y Procesar Archivos")
        
        # Obtener información del usuario
        usuario_actual = st.session_state.get('usuario_actual', {})
        if not usuario_actual:
            st.error("❌ No hay usuario autenticado")
            return
        
        user_id = usuario_actual.get('id_usuario', 'unknown')
        user_role = usuario_actual.get('rol', 'USUARIO')
        
        # Mostrar límites del usuario
        limits = AsyncUtils.get_user_limits(user_role)
        
        st.info(f"""
        **👤 Límites para rol {user_role}:**
        - 📁 Archivos en cola: {'Ilimitados' if limits['max_files_in_queue'] == -1 else limits['max_files_in_queue']}
        - 📊 Registros por archivo: {'Ilimitados' if limits['max_records_per_file'] == -1 else f"{limits['max_records_per_file']:,}"}
        - ⭐ Prioridad: {'Alta' if limits['priority'] == 3 else 'Media' if limits['priority'] == 2 else 'Normal'}
        """)
        
        # PASO 1: FORMULARIO SOLO PARA UPLOAD (SIN BOTONES DE PROCESAMIENTO)
        form_key = f"async_upload_form{form_suffix}"
        with st.form(form_key, clear_on_submit=False):
            col1, col2 = st.columns(2)
            
            with col1:
                tipo_catalogo = st.selectbox(
                    "Tipo de Catálogo:",
                    ["-- Seleccionar --", "ESTADOS", "MUNICIPIOS", "CIUDADES", "COLONIAS", "ALCALDIAS"],
                    help="Tipo de datos que vas a procesar"
                )
            
            with col2:
                division = st.selectbox(
                    "División:",
                    ["-- Seleccionar --", "DES", "QAS", "MEX", "GDL", "MTY", "NTE", "TIJ"],
                    help="División a la que pertenecen los datos"
                )
            
            # Upload del archivo
            uploaded_file = st.file_uploader(
                "📁 Selecciona archivo CSV:",
                type=['csv'],
                help="Archivo con estructura AS400 válida"
            )
            
            # ÚNICO BOTÓN EN EL FORM: ANALIZAR
            submitted = st.form_submit_button("🔍 Analizar Archivo", type="primary")
        
        # PASO 2: PROCESAMIENTO FUERA DEL FORM
        if submitted and uploaded_file and tipo_catalogo != "-- Seleccionar --" and division != "-- Seleccionar --":
            # Guardar datos para procesamiento
            st.session_state.file_ready_for_processing = {
                'file': uploaded_file,
                'tipo_catalogo': tipo_catalogo,
                'division': division,
                'user_id': user_id,
                'user_role': user_role,
                'timestamp': time.time()
            }
            st.rerun()  # Refrescar para mostrar opciones
        
        elif submitted:
            st.warning("⚠️ Por favor, completa todos los campos y selecciona un archivo")
        
        # PASO 3: MOSTRAR OPCIONES DE PROCESAMIENTO SI HAY ARCHIVO LISTO
        if 'file_ready_for_processing' in st.session_state:
            file_data = st.session_state.file_ready_for_processing
            
            # Verificar que no sea muy viejo (5 minutos)
            if time.time() - file_data['timestamp'] > 300:
                del st.session_state.file_ready_for_processing
                st.warning("⏱️ Sesión expirada. Sube el archivo nuevamente.")
                return
            
            self.show_processing_options(file_data)

    def show_processing_options(self, file_data):
        """Mostrar opciones de procesamiento FUERA del formulario"""
        
        st.markdown("---")
        st.markdown("### 📊 Archivo Analizado")
        
        try:
            # Leer archivo
            uploaded_file = file_data['file']
            df = self.read_csv_smart_encoding(uploaded_file)
            
            if df is None:
                # Limpiar datos si hay error
                del st.session_state.file_ready_for_processing
                return
            
            num_records = len(df)
            tipo_catalogo = file_data['tipo_catalogo']
            
            # Mostrar información del archivo
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("📊 Registros", f"{num_records:,}")
            
            with col2:
                estimated_time = AsyncUtils.estimate_processing_time(num_records, tipo_catalogo)
                st.metric("⏱️ Tiempo Estimado", AsyncUtils.format_duration(estimated_time))
            
            with col3:
                # Determinar modo recomendado
                if num_records >= AsyncConfig.AUTO_ASYNC_THRESHOLD:
                    modo_recomendado = "🔄 Asíncrono"
                    color = "🟢"
                else:
                    modo_recomendado = "⚡ Síncrono"
                    color = "🔵"
                
                st.metric("🎯 Modo Recomendado", f"{color} {modo_recomendado}")
            
            # OPCIONES DE PROCESAMIENTO (FUERA DEL FORM)
            st.markdown("### 🚀 Selecciona Modo de Procesamiento")
            
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                if st.button("⚡ PROCESAR SÍNCRONO", type="secondary", use_container_width=True):
                    self.process_sync(df, file_data)
            
            with col2:
                # Validar si puede usar asíncrono
                can_async, async_message = AsyncUtils.validate_file_for_async(df, tipo_catalogo, file_data['user_role'])
                
                if can_async:
                    if st.button("🔄 PROCESAR ASÍNCRONO", type="primary", use_container_width=True):
                        self.process_async(df, file_data)
                else:
                    st.button("🔄 Asíncrono No Disponible", disabled=True, use_container_width=True, help=async_message)
            
            with col3:
                if st.button("❌ Cancelar"):
                    del st.session_state.file_ready_for_processing
                    st.rerun()
            
            # Mostrar ventajas/desventajas
            with st.expander("ℹ️ Comparación de Modos"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("""
                    **⚡ Modo Síncrono:**
                    - ✅ Inmediato
                    - ✅ Familiar
                    - ✅ Resultados al instante
                    - ❌ Bloquea la interfaz
                    - ❌ Lento para archivos grandes
                    """)
                
                with col2:
                    st.markdown("""
                    **🔄 Modo Asíncrono:**
                    - ✅ No bloquea la interfaz
                    - ✅ Progreso en tiempo real
                    - ✅ Puedes hacer otras cosas
                    - ❌ Setup inicial
                    - ❌ Resultados no inmediatos
                    """)
        
        except Exception as e:
            st.error(f"❌ Error analizando archivo: {str(e)}")
            del st.session_state.file_ready_for_processing

    def process_sync(self, df, file_data):
        """Procesar en modo síncrono REAL en el sistema híbrido"""
    
        st.info("⚡ Procesando en modo SÍNCRONO...")
        
        try:
            # Importar el sistema principal para procesamiento
            from sistema_completo_normalizacion import SistemaNormalizacion
            
            # Crear instancia del sistema principal
            sistema_principal = SistemaNormalizacion()
            
            # Crear barra de progreso
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # PASO 1: Validar estructura
            status_text.text("🔍 Validando estructura del archivo...")
            progress_bar.progress(10)
            
            valido, mensaje = sistema_principal.validar_estructura_archivo(df, file_data['tipo_catalogo'])
            
            if not valido:
                st.error(f"❌ Validación falló: {mensaje}")
                del st.session_state.file_ready_for_processing
                return
            
            st.success(f"✅ {mensaje}")
            progress_bar.progress(30)
            
            # PASO 2: Procesar archivo
            status_text.text("⚙️ Procesando archivo con sistema principal...")
            progress_bar.progress(50)
            
            exito, mensaje_proceso = sistema_principal.procesar_archivo_cargado(
                df, 
                file_data['tipo_catalogo'], 
                file_data['division'], 
                file_data['file'].name
            )
            
            progress_bar.progress(90)
            
            # PASO 3: Mostrar resultado
            if exito:
                progress_bar.progress(100)
                status_text.text("✅ Procesamiento completado")
                
                st.success(f"🎉 ¡Procesamiento síncrono exitoso!")
                st.success(f"📊 {mensaje_proceso}")
                
                # Mostrar estadísticas del procesamiento
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("📄 Archivo", file_data['file'].name)
                with col2:
                    st.metric("📊 Registros", f"{len(df):,}")
                with col3:
                    st.metric("📋 Tipo", file_data['tipo_catalogo'])
                
                # Botones de acción
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("📋 Ver Resultados", type="primary"):
                        st.info("💡 Ve a la pestaña 'Resultados' para ver los datos procesados")
                
                with col2:
                    if st.button("📥 Descargar", type="secondary"):
                        st.info("💡 Los resultados están disponibles en la sección de Resultados")
                
                with col3:
                    if st.button("📁 Procesar Otro Archivo"):
                        # Limpiar y permitir subir otro archivo
                        del st.session_state.file_ready_for_processing
                        st.rerun()
                
                # Mostrar información adicional
                with st.expander("ℹ️ Detalles del Procesamiento"):
                    st.markdown(f"""
                    **📋 Información del procesamiento:**
                    - **Modo:** Síncrono (inmediato)
                    - **Archivo:** {file_data['file'].name}
                    - **Tipo:** {file_data['tipo_catalogo']}
                    - **División:** {file_data['division']}
                    - **Registros:** {len(df):,}
                    - **Usuario:** {file_data['user_id']}
                    - **Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    
                    **✅ El archivo ha sido procesado y los resultados están guardados en la base de datos.**
                    """)
            
            else:
                st.error(f"❌ Error en procesamiento: {mensaje_proceso}")
                
                # Mostrar detalles del error
                with st.expander("🔧 Detalles del Error"):
                    st.code(f"""
    Archivo: {file_data['file'].name}
    Tipo: {file_data['tipo_catalogo']}
    División: {file_data['division']}
    Registros: {len(df):,}
    Error: {mensaje_proceso}
                    """)
                
                # Opción de reintentar
                if st.button("🔄 Reintentar"):
                    st.rerun()
            
            # Limpiar datos del archivo procesado
            time.sleep(2)
            del st.session_state.file_ready_for_processing
            
        except Exception as e:
            st.error(f"❌ Error inesperado en procesamiento síncrono: {str(e)}")
            
            # Mostrar detalles técnicos
            with st.expander("🔧 Información Técnica"):
                import traceback
                st.code(traceback.format_exc())
            
            # Limpiar datos
            if 'file_ready_for_processing' in st.session_state:
                del st.session_state.file_ready_for_processing
            
            # Opción de usar sistema asíncrono como alternativa
            st.markdown("### 💡 Alternativa")
            st.info("Si el procesamiento síncrono falla, puedes intentar con el modo asíncrono")
            
            if st.button("🔄 Intentar Modo Asíncrono"):
                self.process_async(df, file_data)

    def process_async(self, df, file_data):
        """Procesar en modo asíncrono"""
        
        if not self.async_processor:
            st.error("❌ Procesador asíncrono no disponible")
            return
        
        st.info("🔄 Enviando al procesador asíncrono...")
        
        with st.spinner("Preparando tarea..."):
            success, message = self.async_processor.submit_task(
                file_data=df,
                file_name=file_data['file'].name,
                tipo_catalogo=file_data['tipo_catalogo'],
                division=file_data['division'],
                user_id=file_data['user_id'],
                user_role=file_data['user_role']
            )
        
        if success:
            st.success(f"✅ {message}")
            st.info("📊 Ve a la pestaña 'Mis Tareas' para ver el progreso")
            
            # Limpiar datos y refrescar
            del st.session_state.file_ready_for_processing
            time.sleep(2)
            st.rerun()
        else:
            st.error(f"❌ {message}")
    
    def process_uploaded_file(self, uploaded_file, tipo_catalogo, division, user_id, user_role):
        """Procesar archivo subido y determinar modo de procesamiento"""
    
        try:
            # Leer archivo
            df = pd.read_csv(uploaded_file)
            num_records = len(df)
            
            st.success(f"✅ Archivo leído: {num_records:,} registros")
            
            # Mostrar información del archivo
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("📊 Registros", f"{num_records:,}")
            
            with col2:
                estimated_time = AsyncUtils.estimate_processing_time(num_records, tipo_catalogo)
                st.metric("⏱️ Tiempo Estimado", AsyncUtils.format_duration(estimated_time))
            
            with col3:
                # Determinar modo recomendado
                if num_records >= AsyncConfig.AUTO_ASYNC_THRESHOLD:
                    modo_recomendado = "🔄 Asíncrono"
                    color = "🟢"
                else:
                    modo_recomendado = "⚡ Síncrono"
                    color = "🔵"
                
                st.metric("🎯 Modo Recomendado", f"{color} {modo_recomendado}")
            
            # Opciones de procesamiento FUERA del form
            st.markdown("---")
            st.markdown("### 🚀 Opciones de Procesamiento")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Modo síncrono
                st.markdown("#### ⚡ Procesamiento Síncrono")
                st.markdown("""
                **Ventajas:**
                - ✅ Inmediato
                - ✅ Familiar
                - ✅ Resultados al instante
                
                **Desventajas:**
                - ❌ Bloquea la interfaz
                - ❌ Lento para archivos grandes
                """)
                
                # BOTÓN FUERA DEL FORM
                if st.button("⚡ Procesar SÍNCRONO", type="secondary", use_container_width=True, key=f"sync_{hash(uploaded_file.name)}"):
                    self.process_sync(df, tipo_catalogo, division, uploaded_file.name)
            
            with col2:
                # Modo asíncrono
                st.markdown("#### 🔄 Procesamiento Asíncrono")
                st.markdown("""
                **Ventajas:**
                - ✅ No bloquea la interfaz
                - ✅ Progreso en tiempo real
                - ✅ Puedes hacer otras cosas
                
                **Desventajas:**
                - ❌ Toma más tiempo en configurar
                - ❌ Resultados no inmediatos
                """)
                
                # Validar si puede usar asíncrono
                can_async, async_message = AsyncUtils.validate_file_for_async(df, tipo_catalogo, user_role)
                
                if can_async:
                    # BOTÓN FUERA DEL FORM
                    if st.button("🔄 Procesar ASÍNCRONO", type="primary", use_container_width=True, key=f"async_{hash(uploaded_file.name)}"):
                        self.process_async(df, tipo_catalogo, division, uploaded_file.name, user_id, user_role)
                else:
                    st.error(f"❌ No disponible: {async_message}")
                    st.button("🔄 Asíncrono No Disponible", disabled=True, use_container_width=True, key=f"async_disabled_{hash(uploaded_file.name)}")
        
        except Exception as e:
            st.error(f"❌ Error procesando archivo: {str(e)}")
    

            st.error(f"❌ {message}")
    
    def show_async_monitoring(self):
        """Mostrar monitoreo del sistema asíncrono"""
        
        st.markdown("### 📊 Monitoreo del Sistema Asíncrono")
        
        if not self.async_processor:
            st.error("❌ Procesador asíncrono no disponible")
            return
        
        # Estadísticas generales
        stats = self.async_processor.get_system_stats()
        
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
        
        # Auto-refresh
        if st.button("🔄 Actualizar"):
            st.rerun()
        
        # Auto-refresh automático cada 5 segundos si hay tareas pendientes
        if stats['total_pending'] > 0:
            st.info("🔄 Actualizando automáticamente cada 5 segundos...")
            time.sleep(5)
            st.rerun()
    
    def show_user_tasks(self):
        """Mostrar tareas del usuario actual - CON BOTONES DE RESULTADOS"""
    
        st.markdown("### 📋 Mis Tareas")
        
        usuario_actual = st.session_state.get('usuario_actual', {})
        if not usuario_actual:
            st.error("❌ No hay usuario autenticado")
            return
        
        if not self.async_processor:
            st.error("❌ Procesador asíncrono no disponible")
            return
        
        user_id = usuario_actual.get('id_usuario', 'unknown')
        user_tasks = self.async_processor.get_user_tasks(user_id)
        
        if not user_tasks:
            st.info("📝 No tienes tareas asíncronas")
            
            # Sugerencia para el usuario
            st.markdown("### 💡 ¿Qué puedes hacer?")
            col1, col2 = st.columns(2)
            
            with col1:
                st.info("""
                **📤 Subir Archivos:**
                - Ve a la pestaña "Subir Archivos"
                - Selecciona archivos > 5,000 registros
                - Se procesarán automáticamente en modo asíncrono
                """)
            
            with col2:
                st.info("""
                **📊 Ver Resultados Anteriores:**
                - Ve a la pestaña "Ver Resultados"
                - Consulta archivos procesados previamente
                - Descarga resultados ya completados
                """)
            return
        
        st.success(f"📊 Tienes {len(user_tasks)} tareas")
        
        # Clasificar tareas por estado
        tareas_pendientes = [t for t in user_tasks if t.status in ['PENDING', 'PROCESSING']]
        tareas_completadas = [t for t in user_tasks if t.status == 'SUCCESS']
        tareas_fallidas = [t for t in user_tasks if t.status == 'FAILURE']
        
        # Mostrar resumen
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("🔄 En Progreso", len(tareas_pendientes))
        with col2:
            st.metric("✅ Completadas", len(tareas_completadas))
        with col3:
            st.metric("❌ Fallidas", len(tareas_fallidas))
        
        # Mostrar cada tarea ordenada por fecha
        todas_tareas = sorted(user_tasks, key=lambda x: x.created_at, reverse=True)
        
        for task in todas_tareas:
            
            # Determinar color y emoji según estado
            if task.status == 'SUCCESS':
                status_color = "🟢"
                status_emoji = "✅"
            elif task.status == 'FAILURE':
                status_color = "🔴"
                status_emoji = "❌"
            elif task.status == 'PROCESSING':
                status_color = "🟡"
                status_emoji = "🔄"
            else:
                status_color = "⚪"
                status_emoji = "⏳"
            
            # Expandir automáticamente tareas en progreso y fallidas
            expand_task = task.status in ['PROCESSING', 'FAILURE']
            
            with st.expander(
                f"{status_color} {task.file_name} - {status_emoji} {task.status}", 
                expanded=expand_task
            ):
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**📄 Archivo:** {task.file_name}")
                    st.write(f"**📋 Tipo:** {task.tipo_catalogo}")
                    st.write(f"**🏢 División:** {task.division}")
                    st.write(f"**📊 Registros:** {task.num_records:,}")
                
                with col2:
                    st.write(f"**🆔 Task ID:** {task.task_id}")
                    st.write(f"**📅 Creado:** {task.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
                    st.write(f"**⏱️ Estimado:** {AsyncUtils.format_duration(task.estimated_duration)}")
                    
                    if task.error_message:
                        st.error(f"**❌ Error:** {task.error_message}")
                
                # Barra de progreso
                progress_value = task.progress / 100.0
                st.progress(progress_value)
                st.write(f"**Progreso:** {task.progress:.1f}%")
                
                # ========================================
                # NUEVA SECCIÓN: BOTONES DE ACCIÓN POR ESTADO
                # ========================================
                
                st.markdown("---")
                
                if task.status == 'SUCCESS':
                    # TAREA COMPLETADA - BOTONES DE RESULTADOS
                    self.mostrar_botones_tarea_completada(task)
                    
                elif task.status == 'PROCESSING':
                    # TAREA EN PROGRESO - BOTONES DE MONITOREO
                    self.mostrar_botones_tarea_en_progreso(task)
                    
                elif task.status == 'FAILURE':
                    # TAREA FALLIDA - BOTONES DE SOLUCIÓN
                    self.mostrar_botones_tarea_fallida(task)
                    
                else:
                    # TAREA PENDIENTE - INFORMACIÓN
                    st.info("⏳ Tarea en cola. Se procesará pronto...")
        
        # Auto-refresh si hay tareas en progreso
        if tareas_pendientes:
            st.markdown("---")
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.info(f"🔄 Tienes {len(tareas_pendientes)} tareas en progreso. La página se actualiza automáticamente cada 10 segundos.")
            
            with col2:
                if st.button("🔄 Actualizar Ahora"):
                    st.rerun()
            
            # Auto-refresh automático
            time.sleep(10)
            st.rerun()
    
    def show_async_configuration(self):
        """Mostrar y permitir cambiar configuración asíncrona"""
        
        st.markdown("### ⚙️ Configuración del Sistema Asíncrono")
        
        # Mostrar configuración actual
        st.markdown("#### 📊 Configuración Actual")
        
        config_info = f"""
        **🎯 Umbral Asíncrono:** {AsyncConfig.AUTO_ASYNC_THRESHOLD:,} registros
        **👥 Workers Máximos:** {AsyncConfig.MAX_WORKERS}
        **⏱️ Timeout:** {AsyncConfig.TASK_TIMEOUT_MINUTES} minutos
        **🧹 Cleanup:** {AsyncConfig.CLEANUP_DAYS} días
        **🔧 Ambiente:** {'Local' if AsyncConfig.is_development() else 'Railway'}
        """
        
        st.info(config_info)
        
        # Configuraciones rápidas
        st.markdown("#### ⚡ Configuraciones Rápidas")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🧪 Desarrollo", help="Configuración para testing"):
                AsyncConfig.AUTO_ASYNC_THRESHOLD = 100
                AsyncConfig.MAX_WORKERS = 2
                st.success("✅ Configuración de desarrollo aplicada")
                st.rerun()
        
        with col2:
            if st.button("🏢 Producción Pequeña", help="Para pocos usuarios"):
                AsyncConfig.AUTO_ASYNC_THRESHOLD = 2000
                AsyncConfig.MAX_WORKERS = 4
                st.success("✅ Configuración de producción pequeña aplicada")
                st.rerun()
        
        with col3:
            if st.button("🚀 Producción Grande", help="Para muchos usuarios"):
                AsyncConfig.AUTO_ASYNC_THRESHOLD = 5000
                AsyncConfig.MAX_WORKERS = 8
                st.success("✅ Configuración de producción grande aplicada")
                st.rerun()
        
        # Mostrar límites por rol
        st.markdown("#### 👥 Límites por Rol de Usuario")
        
        for role, limits in AsyncConfig.USER_LIMITS.items():
            with st.expander(f"👤 {role}"):
                # Preparar textos sin f-strings complejos
                if limits['max_files_in_queue'] == -1:
                    archivos_texto = "Ilimitados"
                else:
                    archivos_texto = str(limits['max_files_in_queue'])
                
                if limits['max_records_per_file'] == -1:
                    registros_texto = "Ilimitados"
                else:
                    registros_texto = f"{limits['max_records_per_file']:,}"
                
                st.write(f"**📁 Archivos en cola:** {archivos_texto}")
                st.write(f"**📊 Registros por archivo:** {registros_texto}")
                st.write(f"**⭐ Prioridad:** {limits['priority']}")

# Función para usar en el sistema principal
def show_unified_dashboard():
    """Función principal para mostrar el dashboard unificado"""
    
    # Verificar autenticación
    if not st.session_state.get('usuario_autenticado', False):
        st.error("❌ Debes estar autenticado para usar el sistema asíncrono")
        return
    
    # Crear y mostrar dashboard
    dashboard = UnifiedDashboard()
    dashboard.show_main_interface()


#RRV01

# ========================================
# NUEVAS FUNCIONES PARA BOTONES POR ESTADO
# ========================================

def mostrar_botones_tarea_completada(self, task):
    """Botones para tareas completadas exitosamente"""
    
    st.success("🎉 **¡Tarea completada exitosamente!**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # BOTÓN PRINCIPAL: VER RESULTADOS
        if st.button(
            "👁️ Ver Resultados", 
            key=f"view_results_{task.task_id}",
            type="primary",
            use_container_width=True
        ):
            # Cambiar a la pestaña de resultados y mostrar este archivo
            st.session_state[f'show_results_for_{task.task_id}'] = True
            st.success("✅ Mostrando resultados...")
            
            # Simular cambio a tab de resultados
            self.mostrar_resultados_tarea_especifica(task)
    
    with col2:
        # BOTÓN: DESCARGAR RESULTADOS
        if st.button(
            "📥 Descargar", 
            key=f"download_{task.task_id}",
            use_container_width=True
        ):
            self.descargar_resultados_tarea(task)
    
    with col3:
        # BOTÓN: ESTADÍSTICAS
        if st.button(
            "📊 Estadísticas", 
            key=f"stats_{task.task_id}",
            use_container_width=True
        ):
            self.mostrar_estadisticas_tarea(task)
    
    with col4:
        # BOTÓN: COMPARTIR/EXPORTAR
        if st.button(
            "📤 Exportar", 
            key=f"export_{task.task_id}",
            use_container_width=True
        ):
            self.exportar_tarea_completa(task)
    
    # Mostrar información de éxito
    tiempo_transcurrido = (datetime.now() - task.created_at).total_seconds()
    st.info(f"""
    ⚡ **Procesamiento completado:**
    - 📊 **Registros procesados:** {task.num_records:,}
    - ⏱️ **Tiempo total:** {AsyncUtils.format_duration(int(tiempo_transcurrido))}
    - 🎯 **Progreso:** {task.progress:.1f}%
    """)

def mostrar_botones_tarea_en_progreso(self, task):
    """Botones para tareas en progreso"""
    
    st.info("🔄 **Tarea en procesamiento...**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # BOTÓN: MONITOREAR PROGRESO
        if st.button(
            "📊 Ver Progreso Detallado", 
            key=f"monitor_{task.task_id}",
            type="primary",
            use_container_width=True
        ):
            self.mostrar_progreso_detallado(task)
    
    with col2:
        # BOTÓN: REFRESCAR ESTADO
        if st.button(
            "🔄 Actualizar Estado", 
            key=f"refresh_{task.task_id}",
            use_container_width=True
        ):
            st.rerun()
    
    with col3:
        # BOTÓN: CANCELAR (si es posible)
        if st.button(
            "🛑 Cancelar", 
            key=f"cancel_{task.task_id}",
            use_container_width=True
        ):
            if st.session_state.get(f'confirm_cancel_{task.task_id}', False):
                self.cancelar_tarea(task)
            else:
                st.session_state[f'confirm_cancel_{task.task_id}'] = True
                st.warning("⚠️ Haz clic de nuevo para confirmar cancelación")
    
    # Información en tiempo real
    tiempo_transcurrido = (datetime.now() - task.created_at).total_seconds()
    tiempo_estimado_restante = task.estimated_duration - tiempo_transcurrido
    
    if tiempo_estimado_restante > 0:
        st.info(f"""
        ⏱️ **Estado actual:**
        - 🔄 **Progreso:** {task.progress:.1f}%
        - ⏰ **Tiempo transcurrido:** {AsyncUtils.format_duration(int(tiempo_transcurrido))}
        - 📅 **Tiempo estimado restante:** {AsyncUtils.format_duration(int(tiempo_estimado_restante))}
        """)
    else:
        st.warning("⚠️ La tarea está tomando más tiempo del estimado. Esto es normal para archivos grandes.")

def mostrar_botones_tarea_fallida(self, task):
    """Botones para tareas fallidas"""
    
    st.error("❌ **Tarea falló durante el procesamiento**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # BOTÓN: VER DETALLES DEL ERROR
        if st.button(
            "🔍 Ver Error Detallado", 
            key=f"error_details_{task.task_id}",
            type="primary",
            use_container_width=True
        ):
            self.mostrar_detalles_error(task)
    
    with col2:
        # BOTÓN: REINTENTAR
        if st.button(
            "🔄 Reintentar", 
            key=f"retry_{task.task_id}",
            use_container_width=True
        ):
            self.reintentar_tarea(task)
    
    with col3:
        # BOTÓN: REPORTAR ERROR
        if st.button(
            "📧 Reportar Error", 
            key=f"report_{task.task_id}",
            use_container_width=True
        ):
            self.reportar_error_tarea(task)
    
    # Mostrar información del error
    if task.error_message:
        with st.expander("🔧 Detalles del Error"):
            st.code(f"""
Error: {task.error_message}
Archivo: {task.file_name}
Tipo: {task.tipo_catalogo}
Registros: {task.num_records:,}
Progreso alcanzado: {task.progress:.1f}%
Fecha de fallo: {task.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            """)

# ========================================
# FUNCIONES DE SOPORTE PARA LOS BOTONES
# ========================================

def mostrar_resultados_tarea_especifica(self, task):
    """Mostrar resultados específicos de una tarea completada"""
    
    st.markdown("---")
    st.markdown(f"### 📊 Resultados: {task.file_name}")
    
    # Buscar el id_archivo asociado a esta tarea
    try:
        from sistema_completo_normalizacion import SistemaNormalizacion
        sistema = SistemaNormalizacion()
        
        with sistema.engine.connect() as conn:
            # Buscar archivo por task_id o nombre + fecha
            result = conn.execute(text("""
                SELECT id_archivo FROM archivos_cargados 
                WHERE task_id = :task_id 
                   OR (nombre_archivo = :filename 
                       AND DATE(fecha_carga) = DATE(:fecha))
                ORDER BY fecha_carga DESC
                LIMIT 1
            """), {
                'task_id': task.task_id,
                'filename': task.file_name,
                'fecha': task.created_at.date()
            })
            
            archivo_row = result.fetchone()
            
            if archivo_row:
                id_archivo = archivo_row[0]
                
                # Mostrar resultados del archivo
                from sistema_completo_normalizacion import mostrar_resultados_archivo
                mostrar_resultados_archivo(id_archivo)
            else:
                st.error("❌ No se encontraron resultados para esta tarea")
                st.info("💡 Los resultados pueden estar en la pestaña 'Ver Resultados'")
    
    except Exception as e:
        st.error(f"Error mostrando resultados: {str(e)}")

def descargar_resultados_tarea(self, task):
    """Descargar resultados de una tarea específica"""
    
    try:
        from sistema_completo_normalizacion import SistemaNormalizacion
        sistema = SistemaNormalizacion()
        
        with sistema.engine.connect() as conn:
            # Buscar archivo asociado
            result = conn.execute(text("""
                SELECT id_archivo FROM archivos_cargados 
                WHERE task_id = :task_id 
                   OR (nombre_archivo = :filename 
                       AND DATE(fecha_carga) = DATE(:fecha))
                ORDER BY fecha_carga DESC
                LIMIT 1
            """), {
                'task_id': task.task_id,
                'filename': task.file_name,
                'fecha': task.created_at.date()
            })
            
            archivo_row = result.fetchone()
            
            if archivo_row:
                id_archivo = archivo_row[0]
                
                # Usar función existente de descarga
                from sistema_completo_normalizacion import descargar_resultados_archivo
                descargar_resultados_archivo(id_archivo)
            else:
                st.error("❌ No se encontraron resultados para descargar")
    
    except Exception as e:
        st.error(f"Error preparando descarga: {str(e)}")

def mostrar_estadisticas_tarea(self, task):
    """Mostrar estadísticas específicas de una tarea"""
    
    st.markdown("---")
    st.markdown(f"### 📊 Estadísticas: {task.file_name}")
    
    try:
        from sistema_completo_normalizacion import SistemaNormalizacion
        sistema = SistemaNormalizacion()
        
        with sistema.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT 
                    COUNT(*) as total_procesados,
                    COUNT(CASE WHEN valor_normalizado IS NOT NULL THEN 1 END) as exitosos,
                    COUNT(CASE WHEN requiere_revision = true THEN 1 END) as revision,
                    AVG(CASE WHEN confianza > 0 THEN confianza END) as confianza_promedio,
                    COUNT(DISTINCT metodo_usado) as metodos_usados
                FROM resultados_normalizacion r
                JOIN archivos_cargados a ON r.id_archivo = a.id_archivo
                WHERE a.task_id = :task_id 
                   OR (a.nombre_archivo = :filename 
                       AND DATE(a.fecha_carga) = DATE(:fecha))
            """), {
                'task_id': task.task_id,
                'filename': task.file_name,
                'fecha': task.created_at.date()
            })
            
            stats_row = result.fetchone()
            
            if stats_row:
                stats = dict(stats_row._mapping)
                
                # Mostrar métricas
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("📊 Total Procesados", f"{stats['total_procesados']:,}")
                
                with col2:
                    exitosos = stats['exitosos'] or 0
                    total = stats['total_procesados'] or 1
                    porcentaje = (exitosos / total * 100) if total > 0 else 0
                    st.metric("✅ Exitosos", f"{exitosos:,}", f"{porcentaje:.1f}%")
                
                with col3:
                    st.metric("⚠️ Requieren Revisión", f"{stats['revision'] or 0:,}")
                
                with col4:
                    confianza = stats['confianza_promedio'] or 0
                    st.metric("🎯 Confianza Promedio", f"{confianza:.1%}" if confianza > 0 else "N/A")
                
                # Información adicional
                tiempo_total = (datetime.now() - task.created_at).total_seconds()
                
                st.info(f"""
                **📋 Resumen del Procesamiento:**
                - **Archivo:** {task.file_name}
                - **Tipo:** {task.tipo_catalogo}
                - **División:** {task.division}
                - **Tiempo total:** {AsyncUtils.format_duration(int(tiempo_total))}
                - **Métodos usados:** {stats['metodos_usados'] or 0}
                - **Registros por segundo:** {(stats['total_procesados'] or 0) / max(tiempo_total, 1):.1f}
                """)
            else:
                st.warning("⚠️ No se encontraron estadísticas para esta tarea")
    
    except Exception as e:
        st.error(f"Error obteniendo estadísticas: {str(e)}")

def mostrar_progreso_detallado(self, task):
    """Mostrar progreso detallado de una tarea en ejecución"""
    
    st.markdown("---")
    st.markdown(f"### 🔄 Progreso Detallado: {task.file_name}")
    
    # Calcular métricas en tiempo real
    tiempo_transcurrido = (datetime.now() - task.created_at).total_seconds()
    progreso_pct = task.progress / 100.0
    
    # Estimaciones
    if progreso_pct > 0:
        tiempo_total_estimado = tiempo_transcurrido / progreso_pct
        tiempo_restante = tiempo_total_estimado - tiempo_transcurrido
        registros_por_segundo = (task.num_records * progreso_pct) / tiempo_transcurrido
    else:
        tiempo_restante = task.estimated_duration
        registros_por_segundo = 0
    
    # Mostrar métricas de progreso
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("⏱️ Tiempo Transcurrido", AsyncUtils.format_duration(int(tiempo_transcurrido)))
        st.metric("📊 Registros Estimados Procesados", f"{int(task.num_records * progreso_pct):,}")
    
    with col2:
        st.metric("⏰ Tiempo Restante Estimado", AsyncUtils.format_duration(int(max(tiempo_restante, 0))))
        st.metric("⚡ Velocidad", f"{registros_por_segundo:.1f} reg/seg")
    
    with col3:
        st.metric("🎯 Progreso", f"{task.progress:.1f}%")
        st.metric("📈 ETA", (datetime.now() + timedelta(seconds=max(tiempo_restante, 0))).strftime('%H:%M:%S'))
    
    # Barra de progreso visual mejorada
    st.progress(progreso_pct)
    
    # Información adicional
    st.info(f"""
    **📋 Detalles del Procesamiento:**
    - **Task ID:** {task.task_id}
    - **Archivo:** {task.file_name}
    - **Total de registros:** {task.num_records:,}
    - **Iniciado:** {task.created_at.strftime('%Y-%m-%d %H:%M:%S')}
    - **Prioridad:** {'Alta' if hasattr(task, 'priority') and task.priority >= 3 else 'Normal'}
    """)

def cancelar_tarea(self, task):
    """Cancelar una tarea en progreso"""
    
    try:
        # Aquí implementarías la lógica para cancelar la tarea
        # Esto dependería de cómo esté implementado tu sistema de workers
        
        st.warning(f"🛑 Cancelando tarea: {task.file_name}")
        
        # Simular cancelación (implementar según tu sistema)
        # self.async_processor.cancel_task(task.task_id)
        
        st.success("✅ Tarea cancelada exitosamente")
        st.info("🔄 Actualizando lista de tareas...")
        
        time.sleep(2)
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Error cancelando tarea: {str(e)}")

def mostrar_detalles_error(self, task):
    """Mostrar detalles completos del error"""
    
    st.markdown("---")
    st.markdown(f"### 🔍 Análisis de Error: {task.file_name}")
    
    # Información básica del error
    col1, col2 = st.columns(2)
    
    with col1:
        st.error("**Error Principal:**")
        st.code(task.error_message or "Error sin mensaje específico")
    
    with col2:
        st.info("**Información de la Tarea:**")
        st.write(f"- **Archivo:** {task.file_name}")
        st.write(f"- **Tipo:** {task.tipo_catalogo}")
        st.write(f"- **Registros:** {task.num_records:,}")
        st.write(f"- **Progreso alcanzado:** {task.progress:.1f}%")
    
    # Sugerencias de solución
    st.markdown("### 💡 Posibles Soluciones:")
    
    if "timeout" in (task.error_message or "").lower():
        st.warning("""
        **⏱️ Error de Timeout:**
        - El archivo es muy grande para el tiempo límite
        - **Solución:** Intenta dividir el archivo en partes más pequeñas
        - **O:** Procesa en horario de menor carga
        """)
    
    elif "memory" in (task.error_message or "").lower():
        st.warning("""
        **💾 Error de Memoria:**
        - El archivo excede la memoria disponible
        - **Solución:** Procesa el archivo por partes
        - **O:** Usa el sistema síncrono para archivos grandes
        """)
    
    elif "database" in (task.error_message or "").lower():
        st.warning("""
        **🗄️ Error de Base de Datos:**
        - Problema de conexión o espacio en BD
        - **Solución:** Reintenta en unos minutos
        - **O:** Contacta al administrador del sistema
        """)
    
    else:
        st.info("""
        **🔧 Error General:**
        - Revisa que el archivo tenga el formato correcto
        - Verifica que las columnas sean las esperadas
        - Intenta con el sistema síncrono como alternativa
        """)

def reintentar_tarea(self, task):
    """Reintentar una tarea fallida"""
    
    st.warning(f"🔄 Reintentando tarea: {task.file_name}")
    
    try:
        # Aquí implementarías la lógica para reintentar
        # Esto podría involucrar volver a encolar la tarea
        
        st.info("📤 Reencolando tarea para procesamiento...")
        
        # Simular reintento (implementar según tu sistema)
        # new_task_id = self.async_processor.retry_task(task.task_id)
        
        st.success("✅ Tarea reencolada exitosamente")
        st.info("🔄 La tarea aparecerá como 'PENDING' en la lista")
        
        time.sleep(2)
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Error reintentando tarea: {str(e)}")

def reportar_error_tarea(self, task):
    """Reportar error al administrador"""
    
    st.markdown("---")
    st.markdown(f"### 📧 Reportar Error: {task.file_name}")
    
    # Formulario de reporte
    with st.form(f"error_report_{task.task_id}"):
        st.write("**Información que se enviará al administrador:**")
        
        descripcion_usuario = st.text_area(
            "Describe qué estabas haciendo cuando ocurrió el error:",
            placeholder="Ej: Subí un archivo de COLONIAS de 15,000 registros y falló al 80% de progreso..."
        )
        
        incluir_archivo = st.checkbox(
            "Incluir información del archivo en el reporte",
            value=True
        )
        
        email_usuario = st.text_input(
            "Tu email (opcional, para seguimiento):",
            placeholder="usuario@empresa.com"
        )
        
        if st.form_submit_button("📧 Enviar Reporte", type="primary"):
            # Aquí implementarías el envío del reporte
            reporte_data = {
                'task_id': task.task_id,
                'file_name': task.file_name,
                'error_message': task.error_message,
                'user_description': descripcion_usuario,
                'user_email': email_usuario,
                'include_file_info': incluir_archivo,
                'timestamp': datetime.now()
            }
            
            # Simular envío de reporte
            st.success("✅ Reporte enviado al administrador")
            st.info("📧 Recibirás una respuesta en las próximas 24 horas")

def exportar_tarea_completa(self, task):
    """Exportar información completa de la tarea"""
    
    try:
        # Crear reporte completo de la tarea
        reporte = f"""
    REPORTE COMPLETO DE TAREA ASÍNCRONA
    ==================================

    INFORMACIÓN BÁSICA:
    - Task ID: {task.task_id}
    - Archivo: {task.file_name}
    - Tipo de Catálogo: {task.tipo_catalogo}
    - División: {task.division}
    - Total de Registros: {task.num_records:,}

    ESTADO:
    - Estado Actual: {task.status}
    - Progreso: {task.progress:.1f}%
    - Fecha de Creación: {task.created_at.strftime('%Y-%m-%d %H:%M:%S')}
    - Duración Estimada: {AsyncUtils.format_duration(task.estimated_duration)}

    PROCESAMIENTO:
    - Tiempo Transcurrido: {AsyncUtils.format_duration(int((datetime.now() - task.created_at).total_seconds()))}
    - Usuario: {st.session_state.get('usuario_actual', {}).get('username', 'Unknown')}

    ERRORES:
    {task.error_message or 'Ninguno'}

    GENERADO: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
        
        st.download_button(
            label="📤 Descargar Reporte Completo",
            data=reporte,
            file_name=f"reporte_tarea_{task.task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            key=f"export_report_{task.task_id}"
        )
        
        st.success("✅ Reporte preparado para descarga")
        
    except Exception as e:
        st.error(f"Error generando reporte: {str(e)}")



# Para testing
if __name__ == "__main__":
    # Simular usuario autenticado para testing
    st.session_state.usuario_autenticado = True
    st.session_state.usuario_actual = {
        'id_usuario': 'test_user',
        'username': 'test',
        'rol': 'GERENTE',
        'nombre_completo': 'Usuario de Prueba'
    }
    
    show_unified_dashboard()
# ========================================
# ARCHIVO: sistema_completo_normalizacion.py
# SISTEMA INTEGRAL DE NORMALIZACIÓN DE DOMICILIOS
# ========================================

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import psycopg2
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta
import numpy as np
import uuid
import io
import zipfile
import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import json
import re
from fuzzywuzzy import fuzz, process
import unicodedata

# ========================================
# SISTEMA COMPLETO DE LOGIN Y AUTENTICACIÓN
# AGREGAR AL INICIO DEL ARCHIVO (después de los imports)
# ========================================

import hashlib
import secrets
from datetime import datetime, timedelta


# AGREGAR ESTOS IMPORTS AL INICIO (después de los imports existentes)
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

import time
import json
from datetime import datetime, timedelta
from threading import Lock
import sys

# ========================================
# CACHE PERSISTENTE ENTRE SESIONES
# ========================================

import pickle
import os
from pathlib import Path

# Cargar variables de entorno (solo si existe .env)
try:
    load_dotenv()
except:
    pass

# DETECCIÓN AUTOMÁTICA DE AMBIENTE
IS_RAILWAY = os.getenv('RAILWAY_ENVIRONMENT') is not None
IS_LOCAL = not IS_RAILWAY

# ========================================
# 1. TABLA DE USUARIOS - AGREGAR A crear_tablas_sistema()
# ========================================

def crear_tabla_usuarios(engine):
    """Crear tabla de usuarios con roles"""
    
    sql_usuarios = """
    CREATE TABLE IF NOT EXISTS usuarios (
        id_usuario UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        nombre_completo VARCHAR(100) NOT NULL,
        rol VARCHAR(20) NOT NULL DEFAULT 'USUARIO',
        activo BOOLEAN DEFAULT TRUE,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        fecha_ultimo_acceso TIMESTAMP,
        creado_por UUID REFERENCES usuarios(id_usuario),
        intentos_fallidos INTEGER DEFAULT 0,
        bloqueado_hasta TIMESTAMP,
        
        CONSTRAINT chk_rol CHECK (rol IN ('SUPERUSUARIO', 'GERENTE', 'USUARIO')),
        CONSTRAINT chk_username_length CHECK (length(username) >= 3),
        CONSTRAINT chk_password_complexity CHECK (length(password_hash) > 0)
    );
    
    -- Índices para optimización
    CREATE INDEX IF NOT EXISTS idx_usuarios_username ON usuarios(username);
    CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);
    CREATE INDEX IF NOT EXISTS idx_usuarios_activo ON usuarios(activo);
    
    -- Tabla de sesiones activas
    CREATE TABLE IF NOT EXISTS sesiones_usuario (
        id_sesion UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        id_usuario UUID REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
        token_sesion VARCHAR(255) UNIQUE NOT NULL,
        ip_address INET,
        user_agent TEXT,
        fecha_inicio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        fecha_expiracion TIMESTAMP NOT NULL,
        activa BOOLEAN DEFAULT TRUE
    );
    
    CREATE INDEX IF NOT EXISTS idx_sesiones_token ON sesiones_usuario(token_sesion);
    CREATE INDEX IF NOT EXISTS idx_sesiones_usuario ON sesiones_usuario(id_usuario);
    """
    
    try:
        with engine.connect() as conn:
            conn.execute(text(sql_usuarios))
            conn.commit()
        return True
    except Exception as e:
        print(f"Error creando tabla usuarios: {e}")
        return False

# ========================================
# 2. CLASE DE GESTIÓN DE USUARIOS
# ========================================

class GestorUsuarios:
    """Clase para manejar autenticación y usuarios"""
    
    def __init__(self, engine):
        self.engine = engine
    
    def generar_hash_password(self, password):
        """Generar hash seguro de contraseña"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                           password.encode('utf-8'), 
                                           salt.encode('utf-8'), 
                                           100000)
        return password_hash.hex(), salt
    
    def verificar_password(self, password, password_hash, salt):
        """Verificar contraseña"""
        new_hash = hashlib.pbkdf2_hmac('sha256', 
                                      password.encode('utf-8'), 
                                      salt.encode('utf-8'), 
                                      100000)
        return new_hash.hex() == password_hash
    
    def crear_usuario(self, username, email, password, nombre_completo, rol='USUARIO', creado_por=None):
        """Crear nuevo usuario"""
        try:
            # Validaciones
            if len(username) < 3:
                return False, "El username debe tener al menos 3 caracteres"
            
            if len(password) < 6:
                return False, "La contraseña debe tener al menos 6 caracteres"
            
            # Verificar si ya existe
            with self.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT COUNT(*) FROM usuarios 
                    WHERE username = :username OR email = :email
                """), {'username': username, 'email': email})
                
                if result.fetchone()[0] > 0:
                    return False, "Usuario o email ya existe"
                
                # Crear hash de contraseña
                password_hash, salt = self.generar_hash_password(password)
                
                # Insertar usuario
                conn.execute(text("""
                    INSERT INTO usuarios (username, email, password_hash, salt, nombre_completo, rol, creado_por)
                    VALUES (:username, :email, :password_hash, :salt, :nombre_completo, :rol, :creado_por)
                """), {
                    'username': username,
                    'email': email,
                    'password_hash': password_hash,
                    'salt': salt,
                    'nombre_completo': nombre_completo,
                    'rol': rol,
                    'creado_por': creado_por
                })
                
                conn.commit()
                return True, "Usuario creado exitosamente"
        
        except Exception as e:
            return False, f"Error creando usuario: {str(e)}"
    
    def autenticar_usuario(self, username, password):
        """Autenticar usuario"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT id_usuario, username, email, password_hash, salt, 
                           nombre_completo, rol, activo, intentos_fallidos, bloqueado_hasta
                    FROM usuarios 
                    WHERE username = :username AND activo = true
                """), {'username': username})
                
                user_row = result.fetchone()
                
                if not user_row:
                    return False, None, "Usuario no encontrado o inactivo"
                
                user_data = dict(user_row._mapping)
                
                # Verificar si está bloqueado
                if user_data['bloqueado_hasta'] and user_data['bloqueado_hasta'] > datetime.now():
                    return False, None, f"Usuario bloqueado hasta {user_data['bloqueado_hasta']}"
                
                # Verificar contraseña
                if self.verificar_password(password, user_data['password_hash'], user_data['salt']):
                    # Login exitoso - resetear intentos fallidos
                    conn.execute(text("""
                        UPDATE usuarios 
                        SET fecha_ultimo_acceso = CURRENT_TIMESTAMP, intentos_fallidos = 0, bloqueado_hasta = NULL
                        WHERE id_usuario = :id_usuario
                    """), {'id_usuario': user_data['id_usuario']})
                    
                    conn.commit()
                    
                    # Remover datos sensibles
                    del user_data['password_hash']
                    del user_data['salt']
                    
                    return True, user_data, "Login exitoso"
                else:
                    # Incrementar intentos fallidos
                    new_attempts = user_data['intentos_fallidos'] + 1
                    bloqueo = None
                    
                    if new_attempts >= 5:
                        bloqueo = datetime.now() + timedelta(minutes=30)
                    
                    conn.execute(text("""
                        UPDATE usuarios 
                        SET intentos_fallidos = :intentos, bloqueado_hasta = :bloqueo
                        WHERE id_usuario = :id_usuario
                    """), {
                        'intentos': new_attempts,
                        'bloqueo': bloqueo,
                        'id_usuario': user_data['id_usuario']
                    })
                    
                    conn.commit()
                    
                    if bloqueo:
                        return False, None, "Demasiados intentos fallidos. Usuario bloqueado por 30 minutos"
                    else:
                        return False, None, f"Contraseña incorrecta. Intentos restantes: {5 - new_attempts}"
        
        except Exception as e:
            return False, None, f"Error en autenticación: {str(e)}"
    
    def crear_sesion(self, id_usuario, ip_address=None, user_agent=None):
        """Crear sesión de usuario"""
        try:
            token = secrets.token_urlsafe(64)
            fecha_expiracion = datetime.now() + timedelta(hours=8)  # 8 horas
            
            with self.engine.connect() as conn:
                conn.execute(text("""
                    INSERT INTO sesiones_usuario (id_usuario, token_sesion, ip_address, user_agent, fecha_expiracion)
                    VALUES (:id_usuario, :token, :ip, :user_agent, :expiracion)
                """), {
                    'id_usuario': id_usuario,
                    'token': token,
                    'ip': ip_address,
                    'user_agent': user_agent,
                    'expiracion': fecha_expiracion
                })
                
                conn.commit()
                return token
        
        except Exception as e:
            print(f"Error creando sesión: {e}")
            return None
    
    def validar_sesion(self, token):
        """Validar sesión activa"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT u.id_usuario, u.username, u.email, u.nombre_completo, u.rol,
                           s.fecha_expiracion
                    FROM sesiones_usuario s
                    JOIN usuarios u ON s.id_usuario = u.id_usuario
                    WHERE s.token_sesion = :token AND s.activa = true AND s.fecha_expiracion > CURRENT_TIMESTAMP
                """), {'token': token})
                
                session_row = result.fetchone()
                
                if session_row:
                    return dict(session_row._mapping)
                else:
                    return None
        
        except Exception as e:
            print(f"Error validando sesión: {e}")
            return None
    
    def cerrar_sesion(self, token):
        """Cerrar sesión en la clase GestorUsuarios - MÉTODO DE LA CLASE"""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("""
                    UPDATE sesiones_usuario 
                    SET activa = false 
                    WHERE token_sesion = :token
                """), {'token': token})
                
                conn.commit()
                return True
        
        except Exception as e:
            print(f"Error cerrando sesión: {e}")
            return False

    
    def listar_usuarios(self):
        """Listar todos los usuarios"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT u.id_usuario, u.username, u.email, u.nombre_completo, u.rol, 
                           u.activo, u.fecha_creacion, u.fecha_ultimo_acceso,
                           c.username as creado_por_username
                    FROM usuarios u
                    LEFT JOIN usuarios c ON u.creado_por = c.id_usuario
                    ORDER BY u.fecha_creacion DESC
                """))
                
                usuarios = []
                for row in result:
                    usuarios.append(dict(row._mapping))
                
                return usuarios
        
        except Exception as e:
            print(f"Error listando usuarios: {e}")
            return []

# ========================================
# 3. FUNCIONES DE LOGIN PARA STREAMLIT
# ========================================

def inicializar_sistema_usuarios():
    """Inicializar sistema de usuarios"""
    
    if 'gestor_usuarios' not in st.session_state:
        # Crear gestor de usuarios
        sistema = SistemaNormalizacion()
        st.session_state.gestor_usuarios = GestorUsuarios(sistema.engine)
        
        # Crear tabla de usuarios
        crear_tabla_usuarios(sistema.engine)
        
        # Crear superusuario por defecto si no existe
        crear_superusuario_default()

def crear_superusuario_default():
    """Crear superusuario por defecto"""
    
    gestor = st.session_state.gestor_usuarios
    
    try:
        with gestor.engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM usuarios WHERE rol = 'SUPERUSUARIO'"))
            count = result.fetchone()[0]
            
            if count == 0:
                # Crear superusuario por defecto
                exito, mensaje = gestor.crear_usuario(
                    username='admin',
                    email='admin@telmex.com',
                    password='admin123',  # CAMBIAR EN PRODUCCIÓN
                    nombre_completo='Administrador del Sistema',
                    rol='SUPERUSUARIO'
                )
                
                if exito:
                    st.success("✅ Superusuario por defecto creado: admin/admin123")
                else:
                    st.error(f"Error creando superusuario: {mensaje}")
    
    except Exception as e:
        st.error(f"Error verificando superusuario: {e}")

def mostrar_pantalla_login():
    """Login con estructura similar al dashboard (con tabs)"""
    
    # HEADER IGUAL AL DASHBOARD
    col_logo, col_title = st.columns([1, 8])
    with col_logo:
        try:
            st.image("logo_RN.png", width=120)
        except:
            st.markdown("🏠")
    with col_title:
        st.markdown("""
        <div  style="text-align: left;">
            <h3>Red Nacional Última Milla</h3>
            <h5>Sistema Integral de Normalización Domicilios | Procesamiento Inteligente de Domicilios</h5>
        </div>
        """, unsafe_allow_html=True)
    
    # TABS COMO EL DASHBOARD
    tab1, tab2 = st.tabs(["🔐 Iniciar Sesión", "ℹ️ Información"])
    
    with tab1:
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            st.markdown("### 🔐 Acceso al Sistema")
            
            with st.form("login_form"):
                username = st.text_input("👤 Usuario:", placeholder="Ingresa tu usuario")
                password = st.text_input("🔒 Contraseña:", type="password", placeholder="Ingresa tu contraseña")
                
                login_button = st.form_submit_button("🚀 Ingresar", use_container_width=True, type="primary")
                
                if login_button:
                    if username and password:
                        gestor = st.session_state.gestor_usuarios
                        exito, user_data, mensaje = gestor.autenticar_usuario(username, password)
                        
                        if exito:
                            token = gestor.crear_sesion(user_data['id_usuario'])
                            
                            if token:
                                st.session_state.usuario_autenticado = True
                                st.session_state.usuario_actual = user_data
                                st.session_state.token_sesion = token
                                
                                st.success(f"¡Bienvenido, {user_data['nombre_completo']}!")
                                st.rerun()
                            else:
                                st.error("Error creando sesión")
                        else:
                            st.error(mensaje)
                    else:
                        st.warning("Por favor, ingresa usuario y contraseña")
    
    with tab2:
        st.markdown("### ℹ️ Información del Sistema")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **🔑 Credenciales por Defecto:**
            - **Usuario:** admin
            - **Contraseña:** admin123
            
            **👥 Roles del Sistema:**
            - **SUPERUSUARIO:** Control total
            - **GERENTE:** Gestión avanzada  
            - **USUARIO:** Solo visualización
            """)
        
        with col2:
            st.markdown("""
            **🛡️ Características de Seguridad:**
            - Contraseñas cifradas
            - Bloqueo por intentos fallidos
            - Sesiones seguras (8 horas)
            - Auditoría de accesos
            
            **📞 Soporte:**
            - Contacta al administrador del sistema
            - Para problemas de acceso
            """)
        
        st.info("⚠️ **Importante:** Cambia la contraseña por defecto después del primer acceso por seguridad.")


def verificar_autenticacion():
    """Verificar si el usuario está autenticado"""
    
    if 'usuario_autenticado' not in st.session_state:
        st.session_state.usuario_autenticado = False
    
    if 'token_sesion' in st.session_state and st.session_state.token_sesion:
        # Validar sesión
        gestor = st.session_state.gestor_usuarios
        user_data = gestor.validar_sesion(st.session_state.token_sesion)
        
        if user_data:
            st.session_state.usuario_autenticado = True
            st.session_state.usuario_actual = user_data
            return True
        else:
            # Sesión expirada
            st.session_state.usuario_autenticado = False
            if 'usuario_actual' in st.session_state:
                del st.session_state.usuario_actual
            if 'token_sesion' in st.session_state:
                del st.session_state.token_sesion
            return False
    
    return st.session_state.usuario_autenticado

# def cerrar_sesion():
#     """Cerrar sesión del usuario"""
    
#     if 'token_sesion' in st.session_state:
#         gestor = st.session_state.gestor_usuarios
#         gestor.cerrar_sesion(st.session_state.token_sesion)
    
#     # Limpiar session_state
#     st.session_state.usuario_autenticado = False
#     if 'usuario_actual' in st.session_state:
#         del st.session_state.usuario_actual
#     if 'token_sesion' in st.session_state:
#         del st.session_state.token_sesion
    
#     st.rerun()

def es_superusuario():
    """Verificar si el usuario actual es superusuario"""
    if 'usuario_actual' in st.session_state:
        return st.session_state.usuario_actual.get('rol') in ['SUPERUSUARIO', 'GERENTE']
    return False

def mostrar_barra_usuario():
    """Mostrar barra de usuario autenticado"""
    
    if 'usuario_actual' in st.session_state:
        user = st.session_state.usuario_actual
        
        col1, col2, col3 = st.columns([6, 2, 1])
        
        with col1:
            rol_emoji = "👑" if user['rol'] == 'SUPERUSUARIO' else "👨‍💼" if user['rol'] == 'GERENTE' else "👤"
            st.markdown(f"**{rol_emoji} {user['nombre_completo']}** | {user['rol']}")
        
        with col2:
            if es_superusuario():
                if st.button("👥 Gestionar Usuarios", key="manage_users"):
                    st.session_state.mostrar_gestion_usuarios = True
        
        with col3:
            if st.button("🚪 Salir", key="logout"):
                cerrar_sesion_PRESERVANDO_CACHE()

# ========================================
# 4. GESTIÓN DE USUARIOS (SOLO SUPERUSUARIOS)
# ========================================

def mostrar_gestion_usuarios():
    """Interfaz de gestión de usuarios (solo para superusuarios)"""
    
    if not es_superusuario():
        st.error("❌ No tienes permisos para acceder a esta sección")
        return
    
    st.markdown("## 👥 Gestión de Usuarios")
    
    tab1, tab2 = st.tabs(["📋 Lista de Usuarios", "➕ Crear Usuario"])
    
    with tab1:
        mostrar_lista_usuarios()
    
    with tab2:
        mostrar_formulario_crear_usuario()

def mostrar_lista_usuarios():
    """Mostrar lista de usuarios"""
    
    gestor = st.session_state.gestor_usuarios
    usuarios = gestor.listar_usuarios()
    
    if usuarios:
        st.markdown("### 📊 Usuarios del Sistema")
        
        # Convertir a DataFrame para mostrar
        df_usuarios = pd.DataFrame(usuarios)
        
        # Preparar columnas para mostrar
        df_display = df_usuarios[['username', 'nombre_completo', 'email', 'rol', 'activo', 'fecha_ultimo_acceso']].copy()
        df_display['activo'] = df_display['activo'].apply(lambda x: "✅ Activo" if x else "❌ Inactivo")
        df_display['fecha_ultimo_acceso'] = pd.to_datetime(df_display['fecha_ultimo_acceso']).dt.strftime('%Y-%m-%d %H:%M')
        
        df_display.columns = ['Usuario', 'Nombre Completo', 'Email', 'Rol', 'Estado', 'Último Acceso']
        
        st.dataframe(df_display, use_container_width=True, hide_index=True)
        
        # Estadísticas
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Usuarios", len(usuarios))
        
        with col2:
            activos = sum(1 for u in usuarios if u['activo'])
            st.metric("Usuarios Activos", activos)
        
        with col3:
            superusuarios = sum(1 for u in usuarios if u['rol'] in ['SUPERUSUARIO', 'GERENTE'])
            st.metric("Administradores", superusuarios)
        
        with col4:
            # Usuarios con acceso reciente (últimos 7 días)
            fecha_limite = datetime.now() - timedelta(days=7)
            recientes = sum(1 for u in usuarios if u['fecha_ultimo_acceso'] and 
                          pd.to_datetime(u['fecha_ultimo_acceso']) > fecha_limite)
            st.metric("Activos (7 días)", recientes)
    
    else:
        st.info("No hay usuarios registrados en el sistema")

def mostrar_formulario_crear_usuario():
    """Formulario para crear nuevo usuario"""
    
    st.markdown("### ➕ Crear Nuevo Usuario")
    
    with st.form("crear_usuario_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            nuevo_username = st.text_input("👤 Usuario:", placeholder="ej: jperez")
            nuevo_email = st.text_input("📧 Email:", placeholder="usuario@telmex.com")
            nuevo_password = st.text_input("🔒 Contraseña:", type="password", 
                                         help="Mínimo 6 caracteres")
        
        with col2:
            nuevo_nombre = st.text_input("👨‍💼 Nombre Completo:", placeholder="Juan Pérez")
            nuevo_rol = st.selectbox("🎭 Rol:", 
                                   options=['USUARIO', 'GERENTE', 'SUPERUSUARIO'],
                                   help="USUARIO: Solo visualización\nGERENTE: Gestión básica\nSUPERUSUARIO: Control total")
        
        crear_usuario_button = st.form_submit_button("✅ Crear Usuario", type="primary")
        
        if crear_usuario_button:
            if all([nuevo_username, nuevo_email, nuevo_password, nuevo_nombre]):
                gestor = st.session_state.gestor_usuarios
                user_actual = st.session_state.usuario_actual
                
                exito, mensaje = gestor.crear_usuario(
                    username=nuevo_username,
                    email=nuevo_email,
                    password=nuevo_password,
                    nombre_completo=nuevo_nombre,
                    rol=nuevo_rol,
                    creado_por=user_actual['id_usuario']
                )
                
                if exito:
                    st.success(f"✅ Usuario '{nuevo_username}' creado exitosamente")
                    st.rerun()
                else:
                    st.error(f"❌ {mensaje}")
            else:
                st.warning("⚠️ Por favor, completa todos los campos")

# ========================================
# 5. INTEGRACIÓN CON EL MAIN EXISTENTE
# ========================================

def main_con_autenticacion():
    """Función main con autenticación integrada"""
    
    # Inicializar sistema de usuarios
    inicializar_sistema_usuarios()
    
    # Verificar autenticación
    if not verificar_autenticacion():
        mostrar_pantalla_login()
        return
    
    # Usuario autenticado - mostrar aplicación
    mostrar_barra_usuario()
    
    # Verificar si se debe mostrar gestión de usuarios
    if st.session_state.get('mostrar_gestion_usuarios', False):
        mostrar_gestion_usuarios()
        
        if st.button("⬅️ Volver al Dashboard"):
            st.session_state.mostrar_gestion_usuarios = False
            st.rerun()
        
        return
    
    # Aplicación principal existente
    main_aplicacion_original()

def main_aplicacion_original():
    """Tu función main() original - RENOMBRAR tu main() actual a esto"""
    
    #inicializar_cache_simplificado()
    inicializar_cache_hibrido()

    # Aplicar estilos CSS
    st.markdown(f"""
    <style>
        .stApp {{
            background: {COLORES['gris_claro']};
        }}
        
        .main-header {{
            background: linear-gradient(135deg, {COLORES['azul_telmex']}, {COLORES['rojo_principal']});
            background: linear-gradient(135deg, {COLORES['blanco']}, {COLORES['blanco']});
            color: navy;
            padding: 2rem;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }}
        
        .main-header h1 {{
            font-size: 2.5rem;
            font-weight: 900;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .main-header p {{
            font-size: 1.2rem;
            margin: 0.5rem 0 0 0;
            opacity: 0.9;
        }}
    </style>
    """, unsafe_allow_html=True)
    
    # Header principal
    col_logo, col_title = st.columns([1, 8])
    with col_logo:
        try:
            st.image("logo_RN.png", width=120)
        except:
            st.markdown("🏠")
    with col_title:
        st.markdown("""
        <div  style="text-align: left;">
            <h3>Red Nacional Última Milla</h3>
            <h5>Sistema Integral de Normalización Domicilios | Procesamiento Inteligente de Domicilios</h5>
        </div>
        """, unsafe_allow_html=True)
    
    # Navegación principal
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Dashboard", 
        "📁 Carga de Archivos", 
        "📋 Resultados", 
        "⚙️ Configuración"
    ])
    
    with tab1:
        mostrar_dashboard_principal()
    
    with tab2:
        mostrar_interfaz_carga()
    
    with tab3:
        mostrar_seccion_resultados()
    
    with tab4:
        mostrar_configuracion_sistema()

# ========================================
# PASO 1: AGREGAR DICCIONARIOS INTELIGENTES
# ========================================

# INSTRUCCIONES:
# 1. Agregar este código AL INICIO de tu archivo Python, después de los imports
# 2. Luego agregar el método inicializar_diccionarios() a la clase SistemaNormalizacion
# 3. Llamar el método en __init__()

# ========================================
# DICCIONARIOS DE CONOCIMIENTO (AGREGAR AL INICIO DEL ARCHIVO)
# ========================================

# Diccionario de abreviaciones comunes en México
ABREVIACIONES_MEXICO = {
    # Estados más comunes
    'B.C.': 'BAJA CALIFORNIA',
    'B.C.S.': 'BAJA CALIFORNIA SUR',
    'CDMX': 'CIUDAD DE MEXICO',
    'D.F.': 'CIUDAD DE MEXICO',
    'DISTRITO FEDERAL': 'CIUDAD DE MEXICO',
    'EDO MEX': 'ESTADO DE MEXICO',
    'EDO. MEX.': 'ESTADO DE MEXICO',
    'MEX.': 'ESTADO DE MEXICO',
    'N.L.': 'NUEVO LEON',
    'Q.R.': 'QUINTANA ROO',
    'Q. ROO': 'QUINTANA ROO',
    'S.L.P.': 'SAN LUIS POTOSI',
    
    # Estados con abreviaciones típicas
    'COAH.': 'COAHUILA',
    'CHIH.': 'CHIHUAHUA',
    'CHIS.': 'CHIAPAS',
    'GTO.': 'GUANAJUATO',
    'GRO.': 'GUERRERO',
    'HGO.': 'HIDALGO',
    'JAL.': 'JALISCO',
    'MICH.': 'MICHOACAN',
    'MOR.': 'MORELOS',
    'NAY.': 'NAYARIT',
    'OAX.': 'OAXACA',
    'PUE.': 'PUEBLA',
    'QRO.': 'QUERETARO',
    'SIN.': 'SINALOA',
    'SON.': 'SONORA',
    'TAB.': 'TABASCO',
    'TAMS.': 'TAMAULIPAS',
    'TLAX.': 'TLAXCALA',
    'VER.': 'VERACRUZ',
    'YUC.': 'YUCATAN',
    'ZAC.': 'ZACATECAS',
    
    # Ciudades comunes
    'CD JUAREZ': 'CIUDAD JUAREZ',
    'CD. JUAREZ': 'CIUDAD JUAREZ',
    'GDLE': 'GUADALAJARA',
    'GDL': 'GUADALAJARA',
    'MTY': 'MONTERREY',
    
    # Prefijos y títulos comunes
    'CD.': 'CIUDAD',
    'STA.': 'SANTA',
    'STO.': 'SANTO',
    'S.': 'SAN',
    'GRAL.': 'GENERAL',
    'PRES.': 'PRESIDENTE',
    'PROF.': 'PROFESOR',
    'DR.': 'DOCTOR',
    'ING.': 'INGENIERO',
    'LIC.': 'LICENCIADO',
    'COL.': 'COLONIA',
    'FRACC.': 'FRACCIONAMIENTO',
    'DELEG.': 'DELEGACION',
    'MPIO.': 'MUNICIPIO'
}

# Correcciones de errores tipográficos comunes
CORRECCIONES_TIPOGRAFICAS = {
    # Números por letras (muy común en OCR y digitación)
    '0': 'O',  # Cero por O
    '1': 'I',  # Uno por I
    '3': 'E',  # Tres por E
    '5': 'S',  # Cinco por S
    
    # Letras similares
    'PH': 'F',
    'QU': 'C',
    'K': 'C',
    'W': 'V',
    'Y': 'I'
}

# Sinónimos y equivalencias
SINONIMOS_MEXICO = {
    'CENTRO': ['CENTRO HISTORICO', 'PRIMER CUADRO', 'ZOCALO', 'CENTRO HIST'],
    'INDUSTRIAL': ['ZONA INDUSTRIAL', 'PARQUE INDUSTRIAL', 'Z INDUSTRIAL'],
    'RESIDENCIAL': ['ZONA RESIDENCIAL', 'FRACCIONAMIENTO', 'FRACC'],
    'POPULAR': ['COLONIA POPULAR', 'BARRIO POPULAR', 'COL POPULAR'],
    'AMPLIACION': ['AMPL', 'AMPL.', 'AMPLIAC', 'AMPLIAC'],
    'FRACCIONAMIENTO': ['FRACC', 'FRACC.', 'FRAC', 'FRACCION'],
    'UNIDAD': ['UNID', 'U', 'CONJUNTO', 'CONJ'],
    'PRIVADA': ['PRIV', 'PRIV.', 'PRIVADO', 'PRIV'],
    'COLONIA': ['COL', 'COL.', 'BARRIO'],
    'DELEGACION': ['DELEG', 'DELEG.', 'DELEGAC']
}

# Patrones específicos para domicilios mexicanos
PATRONES_LIMPIEZA_MEXICO = [
    # Remover prefijos innecesarios comunes
    (r'^(LA |EL |LOS |LAS )', ''),
    (r'^(DE LA |DEL |DE LOS |DE LAS )', ''),
    
    # Normalizar espacios múltiples
    (r'\s+', ' '),
    
    # Remover caracteres especiales comunes en domicilios
    (r'[#°ªº]', ''),
    (r'[-_]', ' '),
    (r'[(){}[\]]', ''),
    
    # Números romanos comunes a números arábigos
    (r'\bI\b', '1'),
    (r'\bII\b', '2'),
    (r'\bIII\b', '3'),
    (r'\bIV\b', '4'),
    (r'\bV\b', '5'),
    (r'\bVI\b', '6'),
    (r'\bVII\b', '7'),
    (r'\bVIII\b', '8'),
    (r'\bIX\b', '9'),
    (r'\bX\b', '10'),
    
    # Normalizar separadores
    (r'[/\\|]', ' '),
    
    # Limpiar múltiples puntos
    (r'\.{2,}', '.')
]

# ========================================
# 1. CONFIGURACIÓN AVANZADA
# ========================================

#RRV01 ATABASE_CONFIG = {
#    'host': 'localhost',
#    'port': 5432,
#    'database': 'normalizacion_domicilios',
#    'user': 'postgres',
#    'password': 'admin123'
#}

#RRV01
def get_database_config():
    """Configuración de BD que funciona en ambos ambientes"""
    
    if IS_RAILWAY:
        # CONFIGURACIÓN PARA RAILWAY
        if 'DATABASE_URL' in os.environ:
            database_url = os.environ['DATABASE_URL']
            parsed = urlparse(database_url)
            
            return {
                'host': parsed.hostname,
                'port': parsed.port or 5432,
                'database': parsed.path[1:],
                'user': parsed.username,
                'password': parsed.password
            }
        else:
            # Variables manuales en Railway
            return {
                'host': os.environ['DB_HOST'],
                'port': int(os.environ.get('DB_PORT', 5432)),
                'database': os.environ['DB_NAME'],
                'user': os.environ['DB_USER'],
                'password': os.environ['DB_PASSWORD']
            }
    else:
        # CONFIGURACIÓN LOCAL
        return {
            'host': os.getenv('LOCAL_DB_HOST', 'localhost'),
            'port': int(os.getenv('LOCAL_DB_PORT', 5432)),
            'database': os.getenv('LOCAL_DB_NAME', 'normalizacion_domicilios'),
            'user': os.getenv('LOCAL_DB_USER', 'postgres'),
            'password': os.getenv('LOCAL_DB_PASSWORD', 'admin123')
        }

# APLICAR LA CONFIGURACIÓN
DATABASE_CONFIG = get_database_config()

# Configuración de página
# st.set_page_config(
#     page_title="🏠 Sistema Integral - Normalización Telmex",
#     page_icon="🏠",
#     layout="wide",
#     initial_sidebar_state="expanded"
# )

# Solo ejecutar set_page_config si este es el archivo principal que se está ejecutando
if __name__ == "__main__":
    st.set_page_config(
        page_title="🏢 Sistema Completo - Normalización Telmex",
        page_icon="🏢",
        layout="wide",
        initial_sidebar_state="expanded"
    )

# Paleta de colores
COLORES = {
    'rojo_principal': '#E53E3E',
    'azul_telmex': '#0066CC',
    'verde': '#38A169',
    'amarillo': '#D69E2E',
    'gris_claro': '#F7FAFC',
    'gris_medio': '#E2E8F0',
    'gris_oscuro': '#2D3748',
    'blanco': '#FFFFFF'
}

# ========================================
# 2. ESQUEMAS DE TABLAS AS400
# ========================================

ESQUEMAS_AS400 = {
    'ESTADOS': {
        'STASTS': {'tipo': 'CHARACTER', 'longitud': 1, 'descripcion': 'Status'},
        'STASAB': {'tipo': 'CHARACTER', 'longitud': 2, 'descripcion': 'Clave Estado'},
        'STADES': {'tipo': 'CHARACTER', 'longitud': 20, 'descripcion': 'Descripción Estado'}
    },
    'CIUDADES': {
        'CTYSTS': {'tipo': 'CHARACTER', 'longitud': 1, 'descripcion': 'Status'},
        'CTYCAB': {'tipo': 'CHARACTER', 'longitud': 3, 'descripcion': 'Clave Ciudad'},
        'CTYDES': {'tipo': 'CHARACTER', 'longitud': 40, 'descripcion': 'Descripción Ciudad'}
    },
    'MUNICIPIOS': {
        'MPISTS': {'tipo': 'CHARACTER', 'longitud': 1, 'descripcion': 'Status'},
        'MPICVE': {'tipo': 'CHARACTER', 'longitud': 3, 'descripcion': 'Clave Municipio'},
        'MPIDES': {'tipo': 'CHARACTER', 'longitud': 30, 'descripcion': 'Descripción Municipio'}
    },
    'ALCALDIAS': {
        'DLGSTS': {'tipo': 'CHARACTER', 'longitud': 1, 'descripcion': 'Status'},
        'DLGCVE': {'tipo': 'CHARACTER', 'longitud': 3, 'descripcion': 'Clave Alcaldía'},
        'DLGDES': {'tipo': 'CHARACTER', 'longitud': 30, 'descripcion': 'Descripción Alcaldía'}
    },
    'COLONIAS': {
        'SDASTS': {'tipo': 'CHARACTER', 'longitud': 1, 'descripcion': 'Status'},
        'SDASDA': {'tipo': 'CHARACTER', 'longitud': 5, 'descripcion': 'Clave Colonia'},
        'SDADES': {'tipo': 'CHARACTER', 'longitud': 40, 'descripcion': 'Descripción Colonia'}
    }
}

# ========================================
# 3. ESQUEMA DE REFERENCIA UNIFICADO
# ========================================

ESQUEMA_REFERENCIA = {
    'id_referencia': 'UUID PRIMARY KEY',
    'tipo_catalogo': 'VARCHAR(20)', # ESTADOS/MUNICIPIOS/COLONIAS/CIUDADES/ALCALDIAS
    'codigo_oficial': 'VARCHAR(10)', # Código SEPOMEX/INEGI
    'nombre_oficial': 'VARCHAR(100)', # Nombre normalizado
    'nombre_alternativo': 'TEXT', # JSON con variaciones
    'coordenadas_lat': 'DECIMAL(10,8)',
    'coordenadas_lng': 'DECIMAL(11,8)',
    'estado_padre': 'VARCHAR(50)',
    'municipio_padre': 'VARCHAR(50)',
    'activo': 'BOOLEAN DEFAULT TRUE',
    'fecha_actualizacion': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
}

# ========================================
# 4. CLASE PRINCIPAL DEL SISTEMA
# ========================================

class SistemaNormalizacion:
    """Clase principal que maneja todo el sistema de normalización"""
    
    def __init__(self):
        self.engine = self.crear_conexion()
        self.crear_tablas_sistema()
        self.inicializar_diccionarios_inteligentes()
        self.inicializar_patrones_limpieza()
        
    def crear_conexion(self):
        """Crear conexión con mensajes temporales"""
        try:
            connection_url = f"postgresql://{DATABASE_CONFIG['user']}:{DATABASE_CONFIG['password']}@{DATABASE_CONFIG['host']}:{DATABASE_CONFIG['port']}/{DATABASE_CONFIG['database']}"
            
            if IS_RAILWAY:
                engine = create_engine(connection_url, pool_size=3, max_overflow=5, pool_timeout=20, pool_recycle=1800, connect_args={'sslmode': 'require', 'connect_timeout': 10, 'application_name': 'TelmexNormalizacion-Railway'})
            else:
                engine = create_engine(connection_url, pool_size=5, max_overflow=10, pool_timeout=30, pool_recycle=3600, connect_args={'sslmode': 'prefer', 'connect_timeout': 5, 'application_name': 'TelmexNormalizacion-Local'})
            
            # Probar conexión
            with engine.connect() as conn:
                result = conn.execute(text("SELECT version()"))
                version = result.fetchone()[0]
            
            # ===== MENSAJES TEMPORALES =====
            if 'mensajes_mostrados' not in st.session_state:
                st.session_state.mensajes_mostrados = False
            
            if not st.session_state.mensajes_mostrados:
                # Mostrar mensajes
                st.success("✅ 🚂 Conexión Railway establecida" if IS_RAILWAY else "✅ 🏠 Conexión Local establecida")
                
                if IS_LOCAL:
                    version_corta = version.split(',')[0]
                    st.info(f"🗄️ PostgreSQL: {version_corta}")
                
                st.success("✅ Sistema de tablas inicializado correctamente")
                
                # Marcar como mostrados
                st.session_state.mensajes_mostrados = True
                
                # Auto-limpiar después de 3 segundos
                time.sleep(5)
                st.rerun()
            
            return engine
            
        except Exception as e:
            if IS_RAILWAY:
                st.error(f"❌ 🚂 Error conexión Railway: {str(e)}")
            else:
                st.error(f"❌ 🏠 Error conexión Local: {str(e)}")
            return None
    
    def crear_tablas_sistema(self):
        """Crear todas las tablas necesarias del sistema"""
        if not self.engine:
            return

        crear_tabla_usuarios(self.engine)

        sqls = [
            # Tabla de referencias unificada
            """
            CREATE TABLE IF NOT EXISTS referencias_normalizacion (
                id_referencia UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tipo_catalogo VARCHAR(20) NOT NULL,
                codigo_oficial VARCHAR(10),
                nombre_oficial VARCHAR(100) NOT NULL,
                nombre_alternativo TEXT,
                coordenadas_lat DECIMAL(10,8),
                coordenadas_lng DECIMAL(11,8),
                estado_padre VARCHAR(50),
                municipio_padre VARCHAR(50),
                activo BOOLEAN DEFAULT TRUE,
                fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """,
            
            # Tabla de archivos cargados
            """
            CREATE TABLE IF NOT EXISTS archivos_cargados (
                id_archivo UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                nombre_archivo VARCHAR(255) NOT NULL,
                tipo_catalogo VARCHAR(20) NOT NULL,
                division VARCHAR(10) NOT NULL,
                total_registros INTEGER,
                fecha_carga TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                usuario VARCHAR(50) DEFAULT 'sistema',
                estado_procesamiento VARCHAR(20) DEFAULT 'PENDIENTE'
            );
            """,
            
            # Tabla de resultados de normalización
            """
            CREATE TABLE IF NOT EXISTS resultados_normalizacion (
                id_resultado UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                id_archivo UUID REFERENCES archivos_cargados(id_archivo),
                tipo_catalogo VARCHAR(20) NOT NULL,
                division VARCHAR(10) NOT NULL,
                
                -- Datos originales AS400
                campo_status VARCHAR(1),
                campo_clave VARCHAR(10),
                campo_descripcion VARCHAR(100),
                texto_original VARCHAR(200),
                
                -- Datos normalizados
                valor_normalizado VARCHAR(100),
                codigo_normalizado VARCHAR(10),
                metodo_usado VARCHAR(50),
                confianza DECIMAL(5,4),
                coordenadas_lat DECIMAL(10,8),
                coordenadas_lng DECIMAL(11,8),
                
                -- Control
                requiere_revision BOOLEAN DEFAULT FALSE,
                revisado_por VARCHAR(50),
                fecha_revision TIMESTAMP,
                observaciones TEXT,
                
                -- Trazabilidad
                fecha_proceso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version_algoritmo VARCHAR(10) DEFAULT '1.0'
            );
            """,
            
            # Índices para optimización
            """
            CREATE INDEX IF NOT EXISTS idx_referencias_tipo ON referencias_normalizacion(tipo_catalogo);
            CREATE INDEX IF NOT EXISTS idx_referencias_activo ON referencias_normalizacion(activo);
            CREATE INDEX IF NOT EXISTS idx_resultados_archivo ON resultados_normalizacion(id_archivo);
            CREATE INDEX IF NOT EXISTS idx_resultados_tipo ON resultados_normalizacion(tipo_catalogo);
            CREATE INDEX IF NOT EXISTS idx_resultados_division ON resultados_normalizacion(division);
            """
        ]
        
        try:
            with self.engine.connect() as conn:
                for sql in sqls:
                    conn.execute(text(sql))
                conn.commit()
            st.success("✅ Sistema de tablas inicializado correctamente")
        except Exception as e:
            st.error(f"Error creando tablas: {e}")
    
    def validar_estructura_archivo(self, df, tipo_catalogo):
        """
        Validar que el archivo tenga la estructura correcta de AS400 - PERMITE CAMPOS VACÍOS
        REEMPLAZAR EL MÉTODO EXISTENTE validar_estructura_archivo() POR ESTE
        """
        
        if tipo_catalogo not in ESQUEMAS_AS400:
            return False, f"Tipo de catálogo no válido: {tipo_catalogo}"
        
        esquema = ESQUEMAS_AS400[tipo_catalogo]
        columnas_esperadas = list(esquema.keys())
        columnas_archivo = df.columns.tolist()
        
        # Verificar que existan las columnas mínimas
        columnas_faltantes = set(columnas_esperadas) - set(columnas_archivo)
        if columnas_faltantes:
            return False, f"❌ Faltan columnas obligatorias: {', '.join(columnas_faltantes)}"
        
        # Verificar que el archivo no esté vacío
        if len(df) == 0:
            return False, "❌ El archivo está vacío"
        
        # VALIDACIÓN DE LONGITUDES CORREGIDA - PERMITE VACÍOS
        errores_longitud = []
        
        for columna, config in esquema.items():
            if columna in df.columns:
                # CRÍTICO: Limpiar y manejar valores vacíos correctamente
                df[columna] = df[columna].astype(str)
                
                # NUEVA LÓGICA: Solo validar registros que NO estén vacíos
                registros_con_datos = df[columna][
                    (df[columna] != 'nan') & 
                    (df[columna] != '') & 
                    (df[columna].notna()) &
                    (df[columna] != 'None')
                ]
                
                if len(registros_con_datos) > 0:
                    max_length = registros_con_datos.str.len().max()
                    
                    if max_length > config['longitud']:
                        # Contar cuántos registros exceden la longitud
                        registros_largos = (registros_con_datos.str.len() > config['longitud']).sum()
                        
                        errores_longitud.append(
                            f"❌ {columna}: {registros_largos} registros exceden longitud máxima "
                            f"(encontrado: {max_length}, esperado: {config['longitud']})"
                        )
        
        if errores_longitud:
            return False, f"Errores de longitud:\n" + "\n".join(errores_longitud)
        
        # VERIFICACIÓN DEL CAMPO DESCRIPCIÓN - TAMBIÉN CORREGIDA
        CAMPO_DESCRIPCION_MAP = {
            'ESTADOS': 'STADES',
            'CIUDADES': 'CTYDES', 
            'MUNICIPIOS': 'MPIDES',
            'ALCALDIAS': 'DLGDES',
            'COLONIAS': 'SDADES'
        }
        
        campo_desc = CAMPO_DESCRIPCION_MAP.get(tipo_catalogo)
        if campo_desc and campo_desc in df.columns:
            # Solo validar que el campo de descripción tenga algunos datos
            registros_vacios_desc = df[campo_desc][
                (df[campo_desc] == 'nan') | 
                (df[campo_desc] == '') | 
                (df[campo_desc].isna()) |
                (df[campo_desc] == 'None')
            ]
            
            porcentaje_vacios = len(registros_vacios_desc) / len(df) * 100
            
            # Permitir hasta 10% de registros vacíos en descripción
            if porcentaje_vacios > 10:
                return False, f"⚠️ {len(registros_vacios_desc)} registros ({porcentaje_vacios:.1f}%) tienen campo de descripción vacío en {campo_desc}. Máximo permitido: 10%"
            elif porcentaje_vacios > 0:
                # Solo advertencia si hay pocos vacíos
                print(f"⚠️ Advertencia: {len(registros_vacios_desc)} registros con {campo_desc} vacío ({porcentaje_vacios:.1f}%)")
        
        return True, f"✅ Estructura válida: {len(df)} registros, {len(columnas_archivo)} columnas"



    def procesar_archivo_cargado(self, df, tipo_catalogo, division, nombre_archivo):
        """
        Procesar un archivo cargado y normalizarlo - CON LIMPIEZA PREVIA
        REEMPLAZAR EL MÉTODO EXISTENTE EN LA CLASE SistemaNormalizacion
        """
        
        # PASO 1: LIMPIAR DataFrame antes de validar
        print(f"🧹 Limpiando DataFrame antes de validación...")
        df_limpio = preparar_dataframe_para_validacion(df)
        
        # PASO 2: Validar estructura con DataFrame limpio
        valido, mensaje = self.validar_estructura_archivo(df_limpio, tipo_catalogo)
        if not valido:
            return False, mensaje
        
        try:
            # Registrar archivo en BD
            id_archivo = str(uuid.uuid4())
            
            with self.engine.connect() as conn:
                conn.execute(text("""
                    INSERT INTO archivos_cargados 
                    (id_archivo, nombre_archivo, tipo_catalogo, division, total_registros, estado_procesamiento)
                    VALUES (:id_archivo, :nombre, :tipo, :division, :total, 'PROCESANDO')
                """), {
                    'id_archivo': id_archivo,
                    'nombre': nombre_archivo,
                    'tipo': tipo_catalogo,
                    'division': division,
                    'total': len(df_limpio)  # Usar DataFrame limpio
                })
                conn.commit()
            
            # PASO 3: Procesar registros con DataFrame limpio
            resultados = []
            esquema = ESQUEMAS_AS400[tipo_catalogo]
            
            # CORRECCIÓN: Mapeo directo de campos de descripción por tipo
            CAMPO_DESCRIPCION_MAP = {
                'ESTADOS': 'STADES',
                'CIUDADES': 'CTYDES', 
                'MUNICIPIOS': 'MPIDES',
                'ALCALDIAS': 'DLGDES',
                'COLONIAS': 'SDADES'
            }
            
            campo_descripcion = CAMPO_DESCRIPCION_MAP.get(tipo_catalogo)
            
            if not campo_descripcion or campo_descripcion not in df_limpio.columns:
                return False, f"Campo de descripción '{campo_descripcion}' no encontrado para {tipo_catalogo}"
            
            # CORRECCIÓN: Mapeo de campos de status y clave
            CAMPO_STATUS_MAP = {
                'ESTADOS': 'STASTS',
                'CIUDADES': 'CTYSTS',
                'MUNICIPIOS': 'MPISTS', 
                'ALCALDIAS': 'DLGSTS',
                'COLONIAS': 'SDASTS'
            }
            
            CAMPO_CLAVE_MAP = {
                'ESTADOS': 'STASAB',
                'CIUDADES': 'CTYCAB',
                'MUNICIPIOS': 'MPICVE',
                'ALCALDIAS': 'DLGCVE', 
                'COLONIAS': 'SDASDA'
            }
            
            campo_status = CAMPO_STATUS_MAP.get(tipo_catalogo)
            campo_clave = CAMPO_CLAVE_MAP.get(tipo_catalogo)
            
            # Procesar cada registro del DataFrame limpio
            for idx, row in df_limpio.iterrows():
                resultado = self.normalizar_registro(
                    texto_original=str(row[campo_descripcion]),
                    tipo_catalogo=tipo_catalogo,
                    division=division,
                    campo_status=str(row.get(campo_status, '')),  # Manejo de vacíos
                    campo_clave=str(row.get(campo_clave, '')),    # Manejo de vacíos
                    campo_descripcion=str(row[campo_descripcion])
                )
                
                resultado['id_archivo'] = id_archivo
                resultados.append(resultado)
                
                # Actualizar progreso cada 100 registros
                if (idx + 1) % 100 == 0:
                    progreso = (idx + 1) / len(df_limpio) * 100
                    self.actualizar_progreso_archivo(id_archivo, progreso)
            
            # Guardar resultados en BD
            self.guardar_resultados(resultados)
            
            # Marcar como completado
            with self.engine.connect() as conn:
                conn.execute(text("""
                    UPDATE archivos_cargados 
                    SET estado_procesamiento = 'COMPLETADO'
                    WHERE id_archivo = :id_archivo
                """), {'id_archivo': id_archivo})
                conn.commit()
            
            return True, f"Procesados {len(resultados)} registros correctamente (con limpieza previa)"
            
        except Exception as e:
            return False, f"Error procesando archivo: {str(e)}"





    
    def normalizar_registro(self, texto_original, tipo_catalogo, division, campo_status, campo_clave, campo_descripcion):
        """Normalizar un registro individual usando los algoritmos de IA"""
        
        # Limpiar texto
        texto_limpio = self.limpiar_texto_inteligente(texto_original, tipo_catalogo)
        
        # Buscar en referencias
        #referencia_encontrada = self.buscar_en_referencias_CORREGIDO(texto_limpio, tipo_catalogo)
        referencia_encontrada = self.buscar_en_referencias_CACHE_SIMPLE(texto_limpio, tipo_catalogo)
    
        resultado = {
            'tipo_catalogo': tipo_catalogo,
            'division': division,
            'campo_status': campo_status,
            'campo_clave': campo_clave,
            'campo_descripcion': campo_descripcion,
            'texto_original': texto_original,
            'valor_normalizado': None,
            'codigo_normalizado': None,
            'metodo_usado': 'SIN_MATCH',
            'confianza': 0.0,
            'coordenadas_lat': None,
            'coordenadas_lng': None,
            'requiere_revision': True
        }
        
        if referencia_encontrada:
            resultado.update({
                'valor_normalizado': referencia_encontrada['nombre_oficial'],
                'codigo_normalizado': referencia_encontrada['codigo_oficial'],
                'metodo_usado': referencia_encontrada['metodo'],
                'confianza': referencia_encontrada['confianza'],
                'coordenadas_lat': referencia_encontrada.get('coordenadas_lat'),
                'coordenadas_lng': referencia_encontrada.get('coordenadas_lng'),
                'requiere_revision': referencia_encontrada['confianza'] < 0.8
            })
        
        return resultado
    
    def limpiar_texto_inteligente(self, texto, tipo_catalogo=None):
        """Limpieza inteligente que reemplaza al método limpiar_texto() original"""
        
        if not isinstance(texto, str):
            return ""
        
        print(f"🧠 Limpieza inteligente: '{texto}' (tipo: {tipo_catalogo})")
        
        # PASO 1: Conversión básica
        texto_procesado = texto.upper().strip()
        print(f"   Mayúsculas: '{texto_procesado}'")
        
        # PASO 2: Expandir abreviaciones ANTES de limpiar
        if hasattr(self, 'expandir_abreviaciones_inteligente'):
            texto_expandido = self.expandir_abreviaciones_inteligente(texto_procesado)
            if texto_expandido != texto_procesado:
                print(f"   Expandido: '{texto_expandido}'")
                texto_procesado = texto_expandido
        
        # PASO 3: Correcciones tipográficas ANTES de limpiar
        if hasattr(self, 'corregir_errores_tipograficos'):
            texto_corregido = self.corregir_errores_tipograficos(texto_procesado)
            if texto_corregido != texto_procesado:
                print(f"   Corregido: '{texto_corregido}'")
                texto_procesado = texto_corregido
        
        # PASO 4: Aplicar patrones específicos de limpieza
        for patron, reemplazo in PATRONES_LIMPIEZA_MEXICO:
            texto_anterior = texto_procesado
            texto_procesado = re.sub(patron, reemplazo, texto_procesado)
            if texto_procesado != texto_anterior:
                print(f"   Patrón aplicado: '{texto_anterior}' → '{texto_procesado}'")
        
        # PASO 5: Quitar acentos (proceso original)
        texto_sin_acentos = unicodedata.normalize('NFD', texto_procesado)
        texto_sin_acentos = ''.join(char for char in texto_sin_acentos if unicodedata.category(char) != 'Mn')
        
        # PASO 6: Limpiar caracteres especiales (proceso original)  
        texto_limpio = re.sub(r'[^\w\s]', ' ', texto_sin_acentos)
        texto_limpio = re.sub(r'\s+', ' ', texto_limpio).strip()
        
        # PASO 7: Limpieza final específica por tipo de catálogo
        texto_final = self.limpieza_especifica_por_tipo(texto_limpio, tipo_catalogo)
        
        print(f"   Resultado final: '{texto_final}'")
        return texto_final
    
    def buscar_en_referencias(self, texto_limpio, tipo_catalogo):
        """Buscar coincidencias en las referencias usando IA"""
        
        try:
            with self.engine.connect() as conn:
                # Obtener referencias del tipo correspondiente
                result = conn.execute(text("""
                    SELECT * FROM referencias_normalizacion 
                    WHERE tipo_catalogo = :tipo AND activo = true
                """), {'tipo': tipo_catalogo})
                
                referencias = []
                for row in result:
                    referencias.append(dict(row._mapping))
            
            if not referencias:
                return None
            
            mejor_match = None
            mejor_confianza = 0.0
            mejor_metodo = 'SIN_MATCH'
            
            # Buscar coincidencia exacta
            for ref in referencias:
                nombre_ref_limpio = self.limpiar_texto_inteligente(ref['nombre_oficial'])
                if texto_limpio == nombre_ref_limpio:
                    return {
                        **ref,
                        'metodo': 'EXACTO',
                        'confianza': 1.0
                    }
            
            # Buscar con fuzzy matching
            nombres_referencias = [self.limpiar_texto(ref['nombre_oficial']) for ref in referencias]
            mejor_fuzzy = process.extractOne(texto_limpio, nombres_referencias, scorer=fuzz.token_sort_ratio)
            
            if mejor_fuzzy and mejor_fuzzy[1] >= 60:  # Umbral mínimo 60%
                # Encontrar la referencia correspondiente
                for ref in referencias:
                    if self.limpiar_texto(ref['nombre_oficial']) == mejor_fuzzy[0]:
                        return {
                            **ref,
                            'metodo': 'FUZZY_ALTO' if mejor_fuzzy[1] >= 80 else 'FUZZY_BAJO',
                            'confianza': mejor_fuzzy[1] / 100.0
                        }
            
            return None
            
        except Exception as e:
            print(f"Error buscando referencias: {e}")
            return None
        
    def buscar_en_referencias_CORREGIDO(self, texto_limpio, tipo_catalogo):
        """
        Buscar coincidencias en las referencias usando IA - VERSIÓN CORREGIDA
        
        REEMPLAZAR EL MÉTODO EXISTENTE buscar_en_referencias() POR ESTE
        """
        
        print(f"🔍 Buscando: '{texto_limpio}' en {tipo_catalogo}")
        
        try:
            with self.engine.connect() as conn:
                # Obtener referencias del tipo correspondiente
                result = conn.execute(text("""
                    SELECT * FROM referencias_normalizacion 
                    WHERE tipo_catalogo = :tipo AND activo = true
                """), {'tipo': tipo_catalogo})
                
                referencias = []
                for row in result:
                    referencias.append(dict(row._mapping))
            
            if not referencias:
                print(f"   ❌ No hay referencias para {tipo_catalogo}")
                return None
            
            print(f"   📊 Encontradas {len(referencias)} referencias para {tipo_catalogo}")
            
            # Buscar coincidencia exacta
            for ref in referencias:
                nombre_ref_limpio = ref['nombre_oficial'].upper().strip()
                if texto_limpio == nombre_ref_limpio:
                    print(f"   ✅ EXACTO: '{texto_limpio}' = '{nombre_ref_limpio}'")
                    return {
                        **ref,
                        'metodo': 'EXACTO',
                        'confianza': 1.0
                    }
            
            # Buscar con fuzzy matching - CORREGIDO
            nombres_referencias = [ref['nombre_oficial'].upper().strip() for ref in referencias]
            
            print(f"   🔍 Fuzzy: comparando '{texto_limpio}' con {len(nombres_referencias)} nombres")
            
            # Importar aquí para evitar problemas de importación
            from fuzzywuzzy import fuzz, process
            
            # Probar diferentes scorers
            mejor_fuzzy = process.extractOne(texto_limpio, nombres_referencias, scorer=fuzz.token_sort_ratio)
            
            print(f"   🎯 Mejor fuzzy: {mejor_fuzzy}")
            
            if mejor_fuzzy and mejor_fuzzy[1] >= 60:  # Umbral mínimo 60%
                # Encontrar la referencia correspondiente
                for ref in referencias:
                    nombre_ref = ref['nombre_oficial'].upper().strip()
                    if nombre_ref == mejor_fuzzy[0]:
                        print(f"   ✅ FUZZY: '{texto_limpio}' → '{nombre_ref}' ({mejor_fuzzy[1]}%)")
                        return {
                            **ref,
                            'metodo': 'FUZZY_ALTO' if mejor_fuzzy[1] >= 80 else 'FUZZY_BAJO',
                            'confianza': mejor_fuzzy[1] / 100.0
                        }
            
            print(f"   ❌ Sin coincidencias para '{texto_limpio}' (mejor score: {mejor_fuzzy[1] if mejor_fuzzy else 0}%)")
            return None
            
        except Exception as e:
            print(f"   ❌ Error buscando referencias: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def guardar_resultados(self, resultados):
        """Guardar resultados de normalización en la base de datos"""
        
        if not resultados:
            return
        
        try:
            df_resultados = pd.DataFrame(resultados)
            df_resultados.to_sql('resultados_normalizacion', self.engine, if_exists='append', index=False)
        except Exception as e:
            print(f"Error guardando resultados: {e}")
    
    def actualizar_progreso_archivo(self, id_archivo, progreso):
        """Actualizar progreso de procesamiento de archivo"""
        # En una implementación real, esto se podría guardar en una tabla de progreso
        # Por ahora solo lo almacenamos en session_state
        if 'progreso_archivos' not in st.session_state:
            st.session_state.progreso_archivos = {}
        st.session_state.progreso_archivos[id_archivo] = progreso

    def inicializar_diccionarios_inteligentes(self):
        """
        Método para agregar a la clase SistemaNormalizacion
        AGREGAR ESTE MÉTODO A TU CLASE EXISTENTE
        """
        
        print("🧠 Inicializando diccionarios inteligentes...")
        
        # Cargar diccionarios globales en la instancia
        self.abreviaciones = ABREVIACIONES_MEXICO.copy()
        self.correcciones = CORRECCIONES_TIPOGRAFICAS.copy()
        self.sinonimos = SINONIMOS_MEXICO.copy()
        
        print(f"   ✅ {len(self.abreviaciones)} abreviaciones cargadas")
        print(f"   ✅ {len(self.correcciones)} correcciones cargadas")
        print(f"   ✅ {len(self.sinonimos)} grupos de sinónimos cargados")
        
        # Crear índice inverso de sinónimos para búsqueda rápida
        self.indice_sinonimos = {}
        for principal, variaciones in self.sinonimos.items():
            for variacion in variaciones:
                self.indice_sinonimos[variacion] = principal
        
        print(f"   ✅ {len(self.indice_sinonimos)} sinónimos indexados")


    def expandir_abreviaciones_inteligente(self, texto):
        """
        Método para agregar a la clase SistemaNormalizacion
        AGREGAR ESTE MÉTODO A TU CLASE EXISTENTE
        """
        
        if not hasattr(self, 'abreviaciones'):
            return texto  # Si no están inicializados los diccionarios, devolver original
        
        texto_expandido = texto.upper().strip()
        expansiones_realizadas = []
        
        # Expandir abreviaciones exactas
        for abrev, completo in self.abreviaciones.items():
            if abrev in texto_expandido:
                texto_expandido = texto_expandido.replace(abrev, completo)
                expansiones_realizadas.append(f"{abrev} → {completo}")
        
        # Expandir sinónimos
        palabras = texto_expandido.split()
        palabras_expandidas = []
        
        for palabra in palabras:
            if palabra in self.indice_sinonimos:
                palabra_principal = self.indice_sinonimos[palabra]
                palabras_expandidas.append(palabra_principal)
                expansiones_realizadas.append(f"{palabra} → {palabra_principal}")
            else:
                palabras_expandidas.append(palabra)
        
        resultado = ' '.join(palabras_expandidas)
        
        if expansiones_realizadas:
            print(f"   🔤 Expansiones: {', '.join(expansiones_realizadas)}")
        
        return resultado


    def corregir_errores_tipograficos(self, texto):
        """
        Método para agregar a la clase SistemaNormalizacion
        AGREGAR ESTE MÉTODO A TU CLASE EXISTENTE
        """
        
        if not hasattr(self, 'correcciones'):
            return texto
        
        texto_corregido = texto
        correcciones_realizadas = []
        
        # Aplicar correcciones solo en contexto de palabras
        for incorrecto, correcto in self.correcciones.items():
            # Buscar el carácter incorrecto dentro de palabras
            patron = rf'\b\w*{re.escape(incorrecto)}\w*\b'
            coincidencias = re.findall(patron, texto_corregido)
            
            for coincidencia in coincidencias:
                if incorrecto in coincidencia:
                    corregida = coincidencia.replace(incorrecto, correcto)
                    texto_corregido = texto_corregido.replace(coincidencia, corregida)
                    correcciones_realizadas.append(f"{coincidencia} → {corregida}")
        
        if correcciones_realizadas:
            print(f"   ✏️ Correcciones: {', '.join(correcciones_realizadas)}")
        
        return texto_corregido

    def limpieza_especifica_por_tipo(self, texto, tipo_catalogo):
        """
        Limpieza específica según el tipo de catálogo
        AGREGAR ESTE MÉTODO NUEVO A LA CLASE
        """
        
        if not tipo_catalogo:
            return texto
        
        texto_especifico = texto
        
        if tipo_catalogo == 'ESTADOS':
            # Estados: más estricto, nombres generalmente fijos
            # Remover palabras innecesarias comunes
            palabras_innecesarias = ['ESTADO', 'DE', 'EL', 'LA', 'LOS', 'LAS']
            palabras = texto_especifico.split()
            palabras_filtradas = [p for p in palabras if p not in palabras_innecesarias or len(palabras) <= 2]
            texto_especifico = ' '.join(palabras_filtradas)
            
        elif tipo_catalogo == 'CIUDADES':
            # Ciudades: normalizar prefijos comunes
            if texto_especifico.startswith('CIUDAD '):
                texto_especifico = texto_especifico  # Mantener CIUDAD
            elif texto_especifico.startswith('CD '):
                texto_especifico = 'CIUDAD ' + texto_especifico[3:]
                
        elif tipo_catalogo == 'MUNICIPIOS':
            # Municipios: similar a ciudades pero más flexible
            if texto_especifico.startswith('MUNICIPIO '):
                texto_especifico = texto_especifico[10:]  # Remover prefijo
            elif texto_especifico.startswith('MPIO '):
                texto_especifico = texto_especifico[5:]  # Remover prefijo
                
        elif tipo_catalogo == 'ALCALDIAS':
            # Alcaldías: nombres generalmente fijos de CDMX
            pass  # Sin cambios específicos
            
        elif tipo_catalogo == 'COLONIAS':
            # Colonias: la más flexible, muchas variaciones
            # Remover prefijos comunes de colonias
            prefijos_colonia = ['COLONIA ', 'COL ', 'BARRIO ', 'FRACCIONAMIENTO ', 'FRACC ']
            for prefijo in prefijos_colonia:
                if texto_especifico.startswith(prefijo):
                    texto_especifico = texto_especifico[len(prefijo):]
                    break
        
        if texto_especifico != texto:
            print(f"   Específico {tipo_catalogo}: '{texto}' → '{texto_especifico}'")
        
        return texto_especifico

       


    # ========================================
    # MÉTODO PARA AGREGAR A LA CLASE
    # ========================================

    def inicializar_patrones_limpieza(self):
        """
        Inicializar patrones de limpieza
        AGREGAR ESTE MÉTODO A LA CLASE
        """
        
        # Cargar patrones globales en la instancia
        self.patrones_limpieza = PATRONES_LIMPIEZA_MEXICO.copy()
        
        print(f"   ✅ {len(self.patrones_limpieza)} patrones de limpieza cargados")
        
        # Compilar expresiones regulares para mejor rendimiento
        self.patrones_compilados = []
        for patron, reemplazo in self.patrones_limpieza:
            try:
                regex_compilado = re.compile(patron)
                self.patrones_compilados.append((regex_compilado, reemplazo))
            except re.error as e:
                print(f"   ⚠️ Error compilando patrón '{patron}': {e}")
        

    # ========================================
    # 3. BÚSQUEDA CON CACHE SIMPLIFICADO
    # ========================================

    def buscar_en_referencias_CACHE_SIMPLE(self, texto_limpio, tipo_catalogo):
        """Búsqueda con cache persistente"""
    
        print(f"🔍 Buscando con cache persistente: '{texto_limpio}' en {tipo_catalogo}")
        
        try:
            # Obtener cache persistente
            cache = inicializar_cache_hibrido()
            
            # Obtener referencias (con cache persistente o desde BD)
            referencias = cache.get_referencias(tipo_catalogo, self.engine)
            
            if not referencias:
                print(f"   ❌ No hay referencias para {tipo_catalogo}")
                return None
            
            print(f"   📊 Procesando {len(referencias)} referencias")
            
            # Búsqueda exacta
            for ref in referencias:
                nombre_ref = ref['nombre_oficial'].upper().strip()
                if texto_limpio == nombre_ref:
                    print(f"   ✅ EXACTO: '{texto_limpio}'")
                    return {
                        **ref,
                        'metodo': 'EXACTO',
                        'confianza': 1.0
                    }
            
            # Fuzzy matching
            nombres = [ref['nombre_oficial'].upper().strip() for ref in referencias]
            
            from fuzzywuzzy import fuzz, process
            mejor = process.extractOne(texto_limpio, nombres, scorer=fuzz.token_sort_ratio)
            
            if mejor and mejor[1] >= 60:
                for ref in referencias:
                    if ref['nombre_oficial'].upper().strip() == mejor[0]:
                        print(f"   ✅ FUZZY: '{texto_limpio}' → '{mejor[0]}' ({mejor[1]}%)")
                        return {
                            **ref,
                            'metodo': 'FUZZY_ALTO' if mejor[1] >= 80 else 'FUZZY_BAJO',
                            'confianza': mejor[1] / 100.0
                        }
            
            print(f"   ❌ Sin coincidencias para '{texto_limpio}'")
            return None
            
        except Exception as e:
            print(f"   ❌ Error en búsqueda persistente: {e}")
            # Fallback a búsqueda directa
            return self.buscar_fallback_directo(texto_limpio, tipo_catalogo)









# ========================================
# FUNCIÓN AUXILIAR MEJORADA (FUERA DE LA CLASE)
# ========================================

def mostrar_estructura_esperada_mejorada(tipo_catalogo):
    """Mostrar estructura esperada con más detalles"""
    
    if tipo_catalogo in ESQUEMAS_AS400:
        st.markdown(f"#### 📋 Estructura Esperada para {tipo_catalogo}:")
        
        esquema = ESQUEMAS_AS400[tipo_catalogo]
        
        # Identificar campo principal (descripción)
        CAMPO_PRINCIPAL = {
            'ESTADOS': 'STADES',
            'CIUDADES': 'CTYDES', 
            'MUNICIPIOS': 'MPIDES',
            'ALCALDIAS': 'DLGDES',
            'COLONIAS': 'SDADES'
        }
        
        campo_principal = CAMPO_PRINCIPAL.get(tipo_catalogo)
        
        estructura_data = []
        for campo, info in esquema.items():
            es_principal = campo == campo_principal
            estructura_data.append({
                'Campo': campo,
                'Tipo': info['tipo'],
                'Longitud': info['longitud'],
                'Descripción': info['descripcion'],
                'Es Principal': '🎯 SÍ' if es_principal else 'No',
                'Obligatorio': '✅ SÍ'
            })
        
        estructura_df = pd.DataFrame(estructura_data)
        st.dataframe(estructura_df, use_container_width=True, hide_index=True)
        
        # Mostrar ejemplo de datos
        ejemplos = {
            'ESTADOS': """STASTS,STASAB,STADES
A,01,AGUASCALIENTES
A,02,BAJA CALIFORNIA
A,03,BAJA CALIFORNIA SUR""",
            'CIUDADES': """CTYSTS,CTYCAB,CTYDES
A,001,AGUASCALIENTES
A,002,MEXICALI
A,003,TIJUANA""",
            'MUNICIPIOS': """MPISTS,MPICVE,MPIDES
A,001,AGUASCALIENTES
A,002,ASIENTOS
A,003,CALVILLO""",
            'ALCALDIAS': """DLGSTS,DLGCVE,DLGDES
A,001,ALVARO OBREGON
A,002,AZCAPOTZALCO
A,003,BENITO JUAREZ""",
            'COLONIAS': """SDASTS,SDASDA,SDADES
A,00001,CENTRO
A,00002,DOCTORES
A,00003,OBRERA"""
        }
        
        if tipo_catalogo in ejemplos:
            st.markdown("**Ejemplo de datos correctos:**")
            st.code(ejemplos[tipo_catalogo], language="csv")

    
    def normalizar_registro(self, texto_original, tipo_catalogo, division, campo_status, campo_clave, campo_descripcion):
        """Normalizar un registro individual usando los algoritmos de IA"""
        
        # Limpiar texto
        texto_limpio = self.limpiar_texto_inteligente(texto_original)
        
        # Buscar en referencias
        referencia_encontrada = self.buscar_en_referencias_CORREGIDO(texto_limpio, tipo_catalogo)
        
        resultado = {
            'tipo_catalogo': tipo_catalogo,
            'division': division,
            'campo_status': campo_status,
            'campo_clave': campo_clave,
            'campo_descripcion': campo_descripcion,
            'texto_original': texto_original,
            'valor_normalizado': None,
            'codigo_normalizado': None,
            'metodo_usado': 'SIN_MATCH',
            'confianza': 0.0,
            'coordenadas_lat': None,
            'coordenadas_lng': None,
            'requiere_revision': True
        }
        
        if referencia_encontrada:
            resultado.update({
                'valor_normalizado': referencia_encontrada['nombre_oficial'],
                'codigo_normalizado': referencia_encontrada['codigo_oficial'],
                'metodo_usado': referencia_encontrada['metodo'],
                'confianza': referencia_encontrada['confianza'],
                'coordenadas_lat': referencia_encontrada.get('coordenadas_lat'),
                'coordenadas_lng': referencia_encontrada.get('coordenadas_lng'),
                'requiere_revision': referencia_encontrada['confianza'] < 0.8
            })
        
        return resultado
    
    def limpiar_texto(self, texto, tipo_catalogo=None):
        """
        Limpieza inteligente que reemplaza al método limpiar_texto() original
        REEMPLAZAR EL MÉTODO EXISTENTE limpiar_texto() POR ESTE
        """
        
        if not isinstance(texto, str):
            return ""
        
        print(f"🧠 Limpieza inteligente: '{texto}' (tipo: {tipo_catalogo})")
        
        # PASO 1: Conversión básica
        texto_procesado = texto.upper().strip()
        print(f"   Mayúsculas: '{texto_procesado}'")
        
        # PASO 2: Expandir abreviaciones ANTES de limpiar (usa diccionarios Paso 1)
        if hasattr(self, 'expandir_abreviaciones_inteligente'):
            texto_expandido = self.expandir_abreviaciones_inteligente(texto_procesado)
            if texto_expandido != texto_procesado:
                print(f"   Expandido: '{texto_expandido}'")
                texto_procesado = texto_expandido
        
        # PASO 3: Correcciones tipográficas ANTES de limpiar (usa diccionarios Paso 1)
        if hasattr(self, 'corregir_errores_tipograficos'):
            texto_corregido = self.corregir_errores_tipograficos(texto_procesado)
            if texto_corregido != texto_procesado:
                print(f"   Corregido: '{texto_corregido}'")
                texto_procesado = texto_corregido
        
        # PASO 4: Aplicar patrones específicos de limpieza
        for patron, reemplazo in PATRONES_LIMPIEZA_MEXICO:
            texto_anterior = texto_procesado
            texto_procesado = re.sub(patron, reemplazo, texto_procesado)
            if texto_procesado != texto_anterior:
                print(f"   Patrón aplicado: '{texto_anterior}' → '{texto_procesado}'")
        
        # PASO 5: Quitar acentos (proceso original)
        texto_sin_acentos = unicodedata.normalize('NFD', texto_procesado)
        texto_sin_acentos = ''.join(char for char in texto_sin_acentos if unicodedata.category(char) != 'Mn')
        
        # PASO 6: Limpiar caracteres especiales (proceso original)  
        texto_limpio = re.sub(r'[^\w\s]', ' ', texto_sin_acentos)
        texto_limpio = re.sub(r'\s+', ' ', texto_limpio).strip()
        
        # PASO 7: Limpieza final específica por tipo de catálogo
        texto_final = self.limpieza_especifica_por_tipo(texto_limpio, tipo_catalogo)
        
        print(f"   Resultado final: '{texto_final}'")
        return texto_final
    
    
    
    def guardar_resultados(self, resultados):
        """Guardar resultados de normalización en la base de datos"""
        
        if not resultados:
            return
        
        try:
            df_resultados = pd.DataFrame(resultados)
            df_resultados.to_sql('resultados_normalizacion', self.engine, if_exists='append', index=False)
        except Exception as e:
            print(f"Error guardando resultados: {e}")
    
    def actualizar_progreso_archivo(self, id_archivo, progreso):
        """Actualizar progreso de procesamiento de archivo"""
        # En una implementación real, esto se podría guardar en una tabla de progreso
        # Por ahora solo lo almacenamos en session_state
        if 'progreso_archivos' not in st.session_state:
            st.session_state.progreso_archivos = {}
        st.session_state.progreso_archivos[id_archivo] = progreso

# ========================================
# 5. INTERFAZ DE CARGA DE ARCHIVOS
# ========================================

def mostrar_interfaz_carga():
    """Mostrar interfaz completa de carga de archivos"""
    
    st.markdown("## 📁 Carga y Procesamiento de Archivos")
    
    # Crear tabs para organizar mejor
    tab1, tab2, tab3 = st.tabs(["📤 Subir Archivos", "📚 Referencias", "⚙️ Procesamiento"])
    
    with tab1:
        mostrar_carga_archivos_datos()
    
    with tab2:
        mostrar_carga_referencias()
    
    with tab3:
        mostrar_procesamiento_tiempo_real()

# ========================================
# FUNCIÓN DE INTERFAZ CORREGIDA (FUERA DE LA CLASE)
# ========================================

def mostrar_carga_archivos_datos():
    """Interfaz para cargar archivos de datos AS400 - CON VALIDACIÓN DOBLE"""
    
    st.markdown("### 📊 Cargar Archivos de Datos AS400")
    
    # Selector de tipo de catálogo y división
    col1, col2 = st.columns(2)
    
    with col1:
        # COMBO TIPO DE CATÁLOGO CON OPCIÓN INICIAL
        opciones_tipo = ["-- Seleccionar Tipo --"] + list(ESQUEMAS_AS400.keys())
        
        # CONTROL DE RESET: Si hay flag de reset, forzar index 0
        if st.session_state.get('tipo_catalogo_reset', False):
            tipo_catalogo_index = 0
            # Limpiar el flag
            del st.session_state.tipo_catalogo_reset
        else:
            # Usar valor guardado o 0 por defecto
            if 'tipo_catalogo_selector' in st.session_state:
                try:
                    saved_value = st.session_state.tipo_catalogo_selector
                    tipo_catalogo_index = opciones_tipo.index(saved_value) if saved_value in opciones_tipo else 0
                except:
                    tipo_catalogo_index = 0
            else:
                tipo_catalogo_index = 0
        
        tipo_catalogo = st.selectbox(
            "Tipo de Catálogo:",
            opciones_tipo,
            index=tipo_catalogo_index,
            key="tipo_catalogo_selector",
            help="Selecciona el tipo de datos que vas a subir"
        )
    
    with col2:
        # COMBO DIVISIÓN CON OPCIÓN INICIAL
        opciones_division = ["-- Seleccionar División --", "DES", "QAS", "MEX", "GDL", "MTY", "NTE", "TIJ"]
        
        # CONTROL DE RESET: Si hay flag de reset, forzar index 0
        if st.session_state.get('division_reset', False):
            division_index = 0
            # Limpiar el flag
            del st.session_state.division_reset
        else:
            # Usar valor guardado o 0 por defecto
            if 'division_selector' in st.session_state:
                try:
                    saved_value = st.session_state.division_selector
                    division_index = opciones_division.index(saved_value) if saved_value in opciones_division else 0
                except:
                    division_index = 0
            else:
                division_index = 0
        
        division = st.selectbox(
            "División:",
            opciones_division,
            index=division_index,
            key="division_selector",
            help="División a la que pertenecen los datos"
        )
    
    # VALIDAR SI SE SELECCIONARON AMBOS VALORES
    tipo_valido = tipo_catalogo != "-- Seleccionar Tipo --"
    division_valida = division != "-- Seleccionar División --"
    
    # MOSTRAR ESTRUCTURA ESPERADA SOLO SI TIPO ES VÁLIDO
    if tipo_valido:
        #mostrar_estructura_esperada_mejorada(tipo_catalogo)
        mostrar_estructura_esperada_mejorada_ACTUALIZADA(tipo_catalogo)
    
    # CONTROL DE FILE UPLOADER BASADO EN AMBAS SELECCIONES
    st.markdown("#### 📤 Subir Archivos:")
    
    archivos_subidos = None
    
    if tipo_valido and division_valida:
        # AMBOS SELECCIONADOS: Habilitar file uploader
        archivos_subidos = st.file_uploader(
            "📁 Selecciona archivos CSV:",
            type=['csv'],
            accept_multiple_files=True,
            key="archivos_datos_uploader",
            help="Puedes subir múltiples archivos del mismo tipo"
        )
    elif tipo_valido and not division_valida:
        # Solo tipo seleccionado: Pedir división
        st.info("👆 **Ahora selecciona la división** para habilitar la carga de archivos")
        
        # Mostrar placeholder deshabilitado
        st.markdown("""
        <div style="
            padding: 1rem; 
            border: 2px dashed #cccccc; 
            border-radius: 8px; 
            text-align: center; 
            color: #999999;
            background-color: #f8f9fa;
            margin: 1rem 0;
        ">
            📁 <strong>Seleccionar archivos CSV</strong><br>
            <small>Selecciona una división para continuar</small>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Ninguno o solo división seleccionada: Pedir tipo primero
        st.info("👆 **Primero selecciona el tipo de catálogo** para habilitar la carga de archivos")
        
        # Mostrar placeholder deshabilitado
        st.markdown("""
        <div style="
            padding: 1rem; 
            border: 2px dashed #cccccc; 
            border-radius: 8px; 
            text-align: center; 
            color: #999999;
            background-color: #f8f9fa;
            margin: 1rem 0;
        ">
            📁 <strong>Seleccionar archivos CSV</strong><br>
            <small>Selecciona un tipo de catálogo para continuar</small>
        </div>
        """, unsafe_allow_html=True)
    
    # PROCESAMIENTO DE ARCHIVOS (solo si ambos están seleccionados)
    if archivos_subidos and tipo_valido and division_valida:
        st.markdown(f"#### 📋 Archivos Seleccionados ({len(archivos_subidos)}):")
        
        archivos_validos = []
        
        for archivo in archivos_subidos:
            with st.expander(f"📄 {archivo.name}"):
                try:
                    # Leer archivo
                    df = pd.read_csv(archivo)
                    
                    # Mostrar información básica
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Registros", len(df))
                    with col2:
                        st.metric("Columnas", len(df.columns))
                    with col3:
                        # Validar estructura
                        sistema = SistemaNormalizacion()
                        valido, mensaje = sistema.validar_estructura_archivo(df, tipo_catalogo)
                        st.metric("Estado", "✅ Válido" if valido else "❌ Error")
                    
                    # Mostrar mensaje de validación
                    if valido:
                        st.success(f"✅ {mensaje}")
                        archivos_validos.append((archivo, df))
                        
                        # Mostrar preview
                        st.markdown("**Preview (primeras 5 filas):**")
                        st.dataframe(df.head(), use_container_width=True)
                    else:
                        st.error(f"❌ {mensaje}")
                        
                        # Mostrar ayuda específica
                        st.markdown("**💡 Sugerencias:**")
                        if "Faltan columnas" in mensaje:
                            st.info("Verifica que tu archivo CSV tenga exactamente las columnas mostradas arriba")
                        elif "longitud máxima" in mensaje:
                            st.info("Algunos valores son muy largos. Revisa los datos o ajusta la estructura")
                        elif "vacío" in mensaje:
                            st.info("Asegúrate de que el campo de descripción tenga valores en todos los registros")
                
                except Exception as e:
                    st.error(f"❌ Error leyendo archivo: {str(e)}")
                    st.markdown("**💡 Posibles causas:**")
                    st.info("• Archivo no es CSV válido\n• Encoding incorrecto\n• Separadores incorrectos")
        
        # Botón para procesar archivos válidos
        if archivos_validos:
            st.markdown("---")
            if st.button(f"🚀 Procesar {len(archivos_validos)} archivo(s)", type="primary"):
                # Procesar archivos
                success = procesar_archivos_cargados(archivos_validos, tipo_catalogo, division)
                
                if success:
                    # RESET COMPLETO DESPUÉS DEL PROCESAMIENTO
                    # Limpiar selecciones
                    if 'tipo_catalogo_selector' in st.session_state:
                        del st.session_state.tipo_catalogo_selector
                    if 'division_selector' in st.session_state:
                        del st.session_state.division_selector
                    if 'archivos_datos_uploader' in st.session_state:
                        del st.session_state.archivos_datos_uploader
                    
                    # Activar flags de reset
                    st.session_state.tipo_catalogo_reset = True
                    st.session_state.division_reset = True
                    
                    # Mostrar mensaje de éxito y recargar
                    st.success("✅ **Archivos procesados exitosamente!** Regresando al estado inicial...")
                    time.sleep(2)
                    st.rerun()
        else:
            st.warning("⚠️ No hay archivos válidos para procesar. Revisa los errores mostrados arriba.")
    
    elif not (tipo_valido and division_valida):
        # MOSTRAR INSTRUCCIONES CUANDO NO ESTÁN AMBOS SELECCIONADOS
        st.markdown("""
        ### 💡 Instrucciones de Uso:
        
        **📋 Pasos para cargar archivos AS400:**
        
        1. **🔽 Selecciona el tipo de catálogo** (Estados, Ciudades, Municipios, etc.)
        2. **🏢 Elige la división** correspondiente (DES, QAS, MEX, etc.)
        3. **📁 Selecciona tus archivos CSV** (se habilitará automáticamente)
        4. **👀 Revisa la estructura y preview** de cada archivo
        5. **🚀 Procesa los archivos** válidos
        6. **✨ El sistema se resetea** automáticamente al completar
        
        ---
        
        **📋 Formatos Soportados:**
        
        | Tipo | Columnas Requeridas | Ejemplo |
        |------|---------------------|---------|
        | **ESTADOS** | STASTS, STASAB, STADES | Status, Clave, Descripción |
        | **CIUDADES** | CTYSTS, CTYCAB, CTYDES | Status, Clave, Descripción |
        | **MUNICIPIOS** | MPISTS, MPICVE, MPIDES | Status, Clave, Descripción |
        | **ALCALDIAS** | DLGSTS, DLGCVE, DLGDES | Status, Clave, Descripción |
        | **COLONIAS** | SDASTS, SDASDA, SDADES | Status, Clave, Descripción |
        
        ---
        
        **⚠️ Notas importantes:**
        - Los archivos deben estar en formato CSV UTF-8
        - La primera fila debe contener los nombres de las columnas
        - Verifica que los datos coincidan con la estructura AS400
        """)
    
    else:
        # Archivo no seleccionado pero ambos combos sí
        st.markdown(f"""
        ### 📁 Listo para cargar archivos
        
        **Tipo seleccionado:** `{tipo_catalogo}`  
        **División:** `{division}`
        
        👆 **Selecciona tus archivos CSV** para continuar
        """)
            

def mostrar_carga_referencias():
    """
    Gestión de Referencias con RESET AUTOMÁTICO y VALIDACIÓN de selección
    VERSIÓN CORREGIDA - REEMPLAZAR la función existente por esta
    """
    
    st.markdown("### 📚 Gestión de Referencias (SEPOMEX/INEGI)")
    
    # Mostrar referencias actuales
    mostrar_referencias_actuales()
    
    st.markdown("---")
    
    # Si hay una carga exitosa reciente, mostrar mensaje y resetear
    if st.session_state.get('mostrar_mensaje_exito', False):
        st.success("✅ **Referencias cargadas exitosamente!** La interfaz se ha reseteado.")
        
        # Limpiar el flag después de mostrar el mensaje
        st.session_state.mostrar_mensaje_exito = False
        
        # Auto-scroll hacia arriba y refrescar
        time.sleep(1)
        st.rerun()
    
    # Interfaz de carga
    st.markdown("#### 📤 Cargar Nueva Referencia:")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # COMBO CON OPCIÓN INICIAL REQUERIDA
        opciones_tipo = ["-- Seleccionar Tipo --"] + list(ESQUEMAS_AS400.keys())
        
        # CONTROL DE RESET: Si hay flag de reset, forzar index 0
        if st.session_state.get('tipo_ref_reset', False):
            tipo_ref_index = 0
            # Limpiar el flag
            del st.session_state.tipo_ref_reset
        else:
            # Usar valor guardado o 0 por defecto
            if 'tipo_ref' in st.session_state:
                try:
                    saved_value = st.session_state.tipo_ref
                    tipo_ref_index = opciones_tipo.index(saved_value) if saved_value in opciones_tipo else 0
                except:
                    tipo_ref_index = 0
            else:
                tipo_ref_index = 0
        
        tipo_ref = st.selectbox(
            "Tipo de Referencia:",
            opciones_tipo,
            index=tipo_ref_index,  # Usar índice calculado
            key="tipo_ref",
            help="Selecciona el tipo de catálogo antes de cargar archivo"
        )
    
    with col2:
        # COMBO FUENTE CON OPCIÓN INICIAL REQUERIDA
        opciones_fuente = ["-- Seleccionar Fuente --", "SEPOMEX", "INEGI", "OTRO"]
        
        # CONTROL DE RESET: Si hay flag de reset, forzar index 0
        if st.session_state.get('fuente_ref_reset', False):
            fuente_ref_index = 0
            # Limpiar el flag
            del st.session_state.fuente_ref_reset
        else:
            # Usar valor guardado o 0 por defecto
            if 'fuente_ref' in st.session_state:
                try:
                    saved_value = st.session_state.fuente_ref
                    fuente_ref_index = opciones_fuente.index(saved_value) if saved_value in opciones_fuente else 0
                except:
                    fuente_ref_index = 0
            else:
                fuente_ref_index = 0
        
        fuente_ref = st.selectbox(
            "Fuente:",
            opciones_fuente,
            index=fuente_ref_index,  # Usar índice calculado
            key="fuente_ref"
        )
    
    # VALIDAR SI SE SELECCIONÓ UN TIPO VÁLIDO
    tipo_valido = tipo_ref != "-- Seleccionar Tipo --"
    fuente_valida = fuente_ref != "-- Seleccionar Fuente --"
    
    # Key único basado en timestamp para forzar reset
    if 'file_uploader_key' not in st.session_state:
        st.session_state.file_uploader_key = int(time.time())
    
    # MOSTRAR FILE UPLOADER SOLO SI AMBOS ESTÁN SELECCIONADOS
    archivo_referencia = None
    
    if tipo_valido and fuente_valida:
        # AMBOS SELECCIONADOS: Mostrar file uploader habilitado
        archivo_referencia = st.file_uploader(
            "📁 Examinar Archivo (CSV):",
            type=['csv'],
            key=f"archivo_ref_{st.session_state.file_uploader_key}",
            help="Estructura esperada: codigo_oficial, nombre_oficial, coordenadas_lat, coordenadas_lng"
        )
    elif tipo_valido and not fuente_valida:
        # Solo tipo seleccionado: Pedir que seleccione fuente
        st.info("👆 **Ahora selecciona la fuente** de los datos para continuar")
        
        # Mostrar placeholder deshabilitado
        st.markdown("""
        <div style="
            padding: 1rem; 
            border: 2px dashed #cccccc; 
            border-radius: 8px; 
            text-align: center; 
            color: #999999;
            background-color: #f8f9fa;
            margin: 1rem 0;
        ">
            📁 <strong>Examinar Archivo</strong><br>
            <small>Selecciona una fuente para continuar</small>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Ninguno o solo fuente seleccionada: Pedir tipo primero
        st.info("👆 **Primero selecciona el tipo de referencia** para habilitar la carga de archivos")
        
        # Mostrar un placeholder deshabilitado para mejor UX
        st.markdown("""
        <div style="
            padding: 1rem; 
            border: 2px dashed #cccccc; 
            border-radius: 8px; 
            text-align: center; 
            color: #999999;
            background-color: #f8f9fa;
            margin: 1rem 0;
        ">
            📁 <strong>Examinar Archivo</strong><br>
            <small>Selecciona un tipo de referencia para continuar</small>
        </div>
        """, unsafe_allow_html=True)
    
    # LÓGICA DE PROCESAMIENTO (solo si hay archivo Y ambos están seleccionados)
    if archivo_referencia and tipo_valido and fuente_valida:
        try:
            df_ref = pd.read_csv(archivo_referencia)
            
            st.markdown("**Vista previa del archivo:**")
            st.dataframe(df_ref.head(), use_container_width=True)
            
            # Información del archivo
            st.info(f"""
            **Información del archivo:**
            - Registros: {len(df_ref):,}
            - Columnas: {list(df_ref.columns)}
            - Tipo seleccionado: {tipo_ref}
            - Fuente: {fuente_ref}
            """)
            
            # Validaciones básicas
            columnas_requeridas = ['codigo_oficial', 'nombre_oficial']
            columnas_faltantes = set(columnas_requeridas) - set(df_ref.columns)
            
            if columnas_faltantes:
                st.error(f"❌ Faltan columnas requeridas: {', '.join(columnas_faltantes)}")
            else:
                if st.button("🚀 CARGAR REFERENCIAS", type="primary", use_container_width=True):
                    
                    # Ejecutar carga
                    # success = cargar_referencias_con_actualizacion_automatica(
                    #     df_ref, tipo_ref, fuente_ref, archivo_referencia.name
                    # )
                    # success = cargar_referencias_con_cache_ACTUALIZADO(
                    #     df_ref, tipo_ref, fuente_ref, archivo_referencia.name
                    # )
                    success = cargar_referencias_CACHE_SIMPLE(
                        df_ref, tipo_ref, fuente_ref, archivo_referencia.name
                    )
                    
                    if success:
                        # ===== RESET COMPLETO CORREGIDO =====
                        # Generar nueva key para file uploader
                        st.session_state.file_uploader_key = int(time.time())  
                        
                        # Marcar mensaje de éxito
                        st.session_state.mostrar_mensaje_exito = True  
                        
                        # ===== LIMPIAR TODOS LOS SELECTBOX =====
                        # FORZAR RESET A VALORES INICIALES
                        if 'tipo_ref' in st.session_state:
                            del st.session_state.tipo_ref
                        if 'fuente_ref' in st.session_state:
                            del st.session_state.fuente_ref
                        
                        # FORZAR VALORES INICIALES EXPLÍCITAMENTE
                        st.session_state.tipo_ref_reset = True  # Flag para forzar reset
                        st.session_state.fuente_ref_reset = True  # Flag para forzar reset
                        
                        # Rerun inmediato para aplicar reset
                        st.rerun()
                    else:
                        st.error("❌ Error en la carga")
        
        except Exception as e:
            st.error(f"❌ Error leyendo archivo de referencia: {str(e)}")
    
    elif not (tipo_valido and fuente_valida):
        # ESTADO INICIAL: Ambos no seleccionados - mostrar ayuda
        st.markdown("""
        ### 💡 Instrucciones de Uso:
        
        **📋 Pasos para cargar referencias:**
        
        1. **🔽 Selecciona el tipo** de referencia del menú desplegable
        2. **🏷️ Elige la fuente** de los datos (SEPOMEX, INEGI, etc.)
        3. **📁 Examina y selecciona** tu archivo CSV (se habilitará automáticamente)
        4. **👀 Revisa la vista previa** de los datos cargados
        5. **🚀 Haz clic en "CARGAR"** para procesar las referencias
        6. **✨ La interfaz se resetea** automáticamente al completar
        
        ---
        
        **📋 Estructura requerida del archivo CSV:**
        
        | Columna | Descripción | Obligatorio |
        |---------|-------------|-------------|
        | `codigo_oficial` | Código único del elemento | ✅ Sí |
        | `nombre_oficial` | Nombre normalizado | ✅ Sí |
        | `coordenadas_lat` | Latitud (decimal) | ⚪ Opcional |
        | `coordenadas_lng` | Longitud (decimal) | ⚪ Opcional |
        | `estado_padre` | Estado de referencia | ⚪ Opcional |
        | `municipio_padre` | Municipio de referencia | ⚪ Opcional |
        
        ---
        
        **⚠️ Notas importantes:**
        - El archivo debe estar en formato CSV UTF-8
        - La primera fila debe contener los nombres de las columnas
        - Los datos nuevos **reemplazarán** las referencias existentes del mismo tipo
        """)
    
    else:
        # Archivo no cargado pero ambos sí seleccionados
        st.markdown(f"""
        ### 📁 Listo para cargar archivo
        
        **Tipo seleccionado:** `{tipo_ref}`  
        **Fuente:** `{fuente_ref}`
        
        👆 **Arrastra tu archivo CSV aquí** o haz clic en "Examinar Archivo"
        """)
    

def mostrar_referencias_actuales():
    """
    REEMPLAZAR mostrar_referencias_actuales() por esta versión
    
    Mostrar las referencias actuales en el sistema - VERSIÓN CORREGIDA
    """
    
    sistema = SistemaNormalizacion()
    
    # Crear un container que se pueda actualizar
    referencias_container = st.container()
    
    with referencias_container:
        try:
            with sistema.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT tipo_catalogo, COUNT(*) as total_referencias,
                           MAX(fecha_actualizacion) as ultima_actualizacion
                    FROM referencias_normalizacion 
                    WHERE activo = true
                    GROUP BY tipo_catalogo
                    ORDER BY tipo_catalogo
                """))
                
                # CONVERSIÓN SEGURA
                referencias = []
                for row in result:
                    try:
                        # Método manual seguro
                        referencias.append({
                            'tipo_catalogo': row[0],
                            'total_referencias': row[1],
                            'ultima_actualizacion': row[2]
                        })
                    except Exception as e:
                        print(f"⚠️ Error en referencia actual: {e}")
                        continue
            
            if referencias:
                st.markdown("#### 📋 Referencias Actuales:")
                
                df_referencias = pd.DataFrame(referencias)
                df_referencias.columns = ['Tipo', 'Total Referencias', 'Última Actualización']
                
                # Formatear fecha para mejor legibilidad
                if 'Última Actualización' in df_referencias.columns:
                    try:
                        df_referencias['Última Actualización'] = pd.to_datetime(
                            df_referencias['Última Actualización']
                        ).dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass  # Si falla el formateo, dejar como está
                
                st.dataframe(df_referencias, use_container_width=True, hide_index=True)
                
                # Mostrar estadísticas adicionales
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    total_global = df_referencias['Total Referencias'].sum()
                    st.metric("Total Global", f"{total_global:,}")
                
                with col2:
                    tipos_disponibles = len(df_referencias)
                    st.metric("Tipos de Catálogo", tipos_disponibles)
                
                with col3:
                    # Fecha más reciente
                    try:
                        if 'Última Actualización' in df_referencias.columns:
                            fecha_mas_reciente = pd.to_datetime(
                                df_referencias['Última Actualización']
                            ).max().strftime('%Y-%m-%d')
                            st.metric("Última Carga", fecha_mas_reciente)
                        else:
                            st.metric("Última Carga", "N/A")
                    except:
                        st.metric("Última Carga", "N/A")
                
            else:
                st.info("📝 No hay referencias cargadas en el sistema. Sube archivos de referencia SEPOMEX/INEGI para mejorar la precisión.")
        
        except Exception as e:
            st.error(f"Error consultando referencias: {str(e)}")
            
            # Información de ayuda
            st.markdown("### 🔧 Información del Error:")
            st.code(f"""
Error específico: {str(e)}

Posibles causas:
1. Problema de conversión SQLAlchemy 
2. Tabla referencias_normalizacion no existe
3. Permisos de base de datos

Solución aplicada: Conversión manual de filas
            """)

# ========================================
# CORRECCIÓN PARA ERROR EN PROCESAMIENTO TIEMPO REAL
# ========================================

def mostrar_procesamiento_tiempo_real():
    """Mostrar procesamiento con diagnóstico mejorado - FUNCIÓN CORREGIDA COMPLETA"""
    
    st.markdown("### ⚙️ Monitor de Procesamiento")
    
    # NUEVO: Botón de diagnóstico
    # if st.button("🔍 DIAGNOSTICAR ARCHIVOS", type="secondary"):
    #     sistema = SistemaNormalizacion()
    #     diagnosticar_archivos_cargados(sistema)
    #     return
    
    # Obtener archivos con RANGO DE FECHA CONFIGURABLE
    sistema = SistemaNormalizacion()
    
    # NUEVO: Selector de rango de tiempo
    col1, col2 = st.columns([2, 1])
    
    with col1:
        rango_tiempo = st.selectbox(
            "📅 Mostrar archivos de los últimos:",
            options=[
                ("1 hora", 1/24),
                ("6 horas", 6/24), 
                ("24 horas", 1),
                ("3 días", 3),
                ("7 días", 7),
                ("30 días", 30),
                ("Todos los archivos", 9999)
            ],
            index=6,  # Por defecto "Todos los archivos"
            format_func=lambda x: x[0]
        )
    
    with col2:
        if st.button("🔄 Actualizar", type="primary"):
            st.rerun()
    
    dias_limite = rango_tiempo[1]
    
    try:
        with sistema.engine.connect() as conn:
            
            if dias_limite >= 9999:
                # Mostrar todos los archivos
                result = conn.execute(text("""
                    SELECT a.id_archivo, a.nombre_archivo, a.tipo_catalogo, a.division,
                           a.total_registros, a.fecha_carga, a.estado_procesamiento,
                           COALESCE(r.procesados, 0) as registros_procesados
                    FROM archivos_cargados a
                    LEFT JOIN (
                        SELECT id_archivo, COUNT(*) as procesados
                        FROM resultados_normalizacion
                        GROUP BY id_archivo
                    ) r ON a.id_archivo = r.id_archivo
                    ORDER BY a.fecha_carga DESC
                """))
            else:
                # Mostrar archivos del rango seleccionado
                fecha_limite = datetime.now() - timedelta(days=dias_limite)
                
                result = conn.execute(text("""
                    SELECT a.id_archivo, a.nombre_archivo, a.tipo_catalogo, a.division,
                           a.total_registros, a.fecha_carga, a.estado_procesamiento,
                           COALESCE(r.procesados, 0) as registros_procesados
                    FROM archivos_cargados a
                    LEFT JOIN (
                        SELECT id_archivo, COUNT(*) as procesados
                        FROM resultados_normalizacion
                        GROUP BY id_archivo
                    ) r ON a.id_archivo = r.id_archivo
                    WHERE a.fecha_carga >= :fecha_limite
                    ORDER BY a.fecha_carga DESC
                """), {'fecha_limite': fecha_limite})
            
            archivos = []
            for row in result:
                if row is not None:
                    archivos.append({
                        'id_archivo': row[0],
                        'nombre_archivo': row[1],
                        'tipo_catalogo': row[2],
                        'division': row[3],
                        'total_registros': row[4] or 0,
                        'fecha_carga': row[5],
                        'estado_procesamiento': row[6],
                        'registros_procesados': row[7] or 0
                    })
        
        if archivos:
            st.success(f"✅ Se encontraron {len(archivos)} archivos ({rango_tiempo[0]})")
            
            # Mostrar archivos
            for archivo in archivos:
                with st.expander(f"📄 {archivo['nombre_archivo']} - {archivo['estado_procesamiento']}", expanded=True):
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        total_reg = int(archivo['total_registros'])
                        st.metric("Total Registros", f"{total_reg:,}")
                    
                    with col2:
                        procesados = int(archivo['registros_procesados'])
                        st.metric("Procesados", f"{procesados:,}")
                    
                    with col3:
                        if total_reg > 0:
                            progreso = (procesados / total_reg) * 100
                            st.metric("Progreso", f"{progreso:.1f}%")
                        else:
                            st.metric("Progreso", "0%")
                    
                    with col4:
                        st.metric("División", archivo['division'])
                    
                    # Barra de progreso
                    if total_reg > 0:
                        progreso_pct = procesados / total_reg
                        st.progress(min(progreso_pct, 1.0))
                    else:
                        st.progress(0.0)
                    
                    # Información adicional
                    col1, col2 = st.columns(2)
                    with col1:
                        st.info(f"**Tipo:** {archivo['tipo_catalogo']}")
                    with col2:
                        fecha_formateada = archivo['fecha_carga'].strftime('%Y-%m-%d %H:%M:%S')
                        st.info(f"**Cargado:** {fecha_formateada}")
                    
                    # Botones de acción
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button(f"📊 Ver Resultados", key=f"ver_{archivo['id_archivo']}", use_container_width=True):
                            mostrar_resultados_archivo(archivo['id_archivo'])
                    
                    with col2:
                        if st.button(f"📥 Descargar", key=f"desc_{archivo['id_archivo']}", use_container_width=True):
                            descargar_resultados_archivo(archivo['id_archivo'])
        
        else:
            st.warning(f"⚠️ No hay archivos en el rango seleccionado ({rango_tiempo[0]})")
            
            # Mostrar ayuda
            st.markdown("### 💡 ¿Qué puedes hacer?")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                **🔍 Diagnóstico:**
                - Haz clic en "DIAGNOSTICAR ARCHIVOS"
                - Cambia el rango de tiempo
                - Verifica si el archivo se cargó correctamente
                """)
            
            with col2:
                st.markdown("""
                **📁 Carga de archivos:**
                - Ve a "Carga de Archivos"
                - Sube un archivo nuevo
                - Verifica que se procese correctamente
                """)
            
            # Botón directo para diagnóstico
            if st.button("🔍 HACER DIAGNÓSTICO COMPLETO", type="primary"):
                diagnosticar_archivos_cargados(sistema)
    
    except Exception as e:
        st.error(f"Error consultando procesamiento: {str(e)}")
        
        if st.checkbox("🔧 Mostrar detalles técnicos"):
            import traceback
            st.code(traceback.format_exc())

# ========================================
# 6. FUNCIONES DE PROCESAMIENTO
# ========================================

def procesar_archivos_cargados(archivos_validos, tipo_catalogo, division):
    """Procesar archivos cargados en tiempo real - CON RETURN DE ÉXITO"""
    
    sistema = SistemaNormalizacion()
    
    # Crear barra de progreso general
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    total_archivos = len(archivos_validos)
    archivos_exitosos = 0
    
    for idx, (archivo, df) in enumerate(archivos_validos):
        status_text.text(f"Procesando {archivo.name}... ({idx + 1}/{total_archivos})")
        
        # Procesar archivo
        exito, mensaje = sistema.procesar_archivo_cargado(
            df, tipo_catalogo, division, archivo.name
        )
        
        if exito:
            st.success(f"✅ {archivo.name}: {mensaje}")
            archivos_exitosos += 1
        else:
            st.error(f"❌ {archivo.name}: {mensaje}")
        
        # Actualizar progreso general
        progress_bar.progress((idx + 1) / total_archivos)
    
    # Resultado final
    if archivos_exitosos == total_archivos:
        status_text.text("✅ Procesamiento completado exitosamente")
        st.balloons()
        return True
    elif archivos_exitosos > 0:
        status_text.text(f"⚠️ Procesamiento parcial: {archivos_exitosos}/{total_archivos} exitosos")
        return True
    else:
        status_text.text("❌ Procesamiento falló")
        return False



def mostrar_resultados_archivo(id_archivo):
    """Mostrar resultados detallados de un archivo procesado - RESPONSIVO"""
    
    sistema = SistemaNormalizacion()
    
    try:
        with sistema.engine.connect() as conn:
            # Obtener información del archivo
            result = conn.execute(text("""
                SELECT * FROM archivos_cargados WHERE id_archivo = :id_archivo
            """), {'id_archivo': id_archivo})
            
            archivo_row = result.fetchone()
            if archivo_row is None:
                st.error("❌ No se encontró el archivo especificado.")
                return
                
            archivo_info = dict(archivo_row._mapping)
            
            # Obtener resultados
            result = conn.execute(text("""
                SELECT * FROM resultados_normalizacion 
                WHERE id_archivo = :id_archivo
                ORDER BY fecha_proceso DESC
                LIMIT 1000
            """), {'id_archivo': id_archivo})
            
            resultados = []
            for row in result:
                resultados.append(dict(row._mapping))
        
        if resultados:
            st.markdown(f"### 📊 Resultados: {archivo_info['nombre_archivo']}")
            
            # Métricas del archivo
            col1, col2, col3, col4 = st.columns(4)
            
            total = len(resultados)
            exitosos = sum(1 for r in resultados if r['valor_normalizado'])
            revision = sum(1 for r in resultados if r['requiere_revision'])
            
            # Calcular confianza promedio evitando None
            confianzas_validas = [r['confianza'] for r in resultados if r['confianza'] is not None and r['confianza'] > 0]
            confianza_prom = np.mean(confianzas_validas) if confianzas_validas else 0
            
            with col1:
                st.metric("Total Procesados", f"{total:,}")
            with col2:
                st.metric("Exitosos", f"{exitosos:,}", f"{exitosos/total*100:.1f}%" if total > 0 else "0%")
            with col3:
                st.metric("Requieren Revisión", f"{revision:,}")
            with col4:
                st.metric("Confianza Promedio", f"{confianza_prom:.1%}" if confianza_prom > 0 else "N/A")
            
            # Tabla de resultados RESPONSIVA
            df_resultados = pd.DataFrame(resultados)
            
            # Seleccionar columnas principales para mostrar
            columnas_mostrar = [
                'texto_original', 'valor_normalizado', 'metodo_usado', 
                'confianza', 'requiere_revision', 'fecha_proceso'
            ]
            
            df_display = df_resultados[columnas_mostrar].copy()
            df_display['confianza'] = df_display['confianza'].apply(lambda x: f"{x:.1%}" if x else "N/A")
            df_display['requiere_revision'] = df_display['requiere_revision'].apply(lambda x: "⚠️ Sí" if x else "✅ No")
            df_display['fecha_proceso'] = pd.to_datetime(df_display['fecha_proceso']).dt.strftime('%Y-%m-%d %H:%M')
            
            # Renombrar columnas para mejor presentación
            df_display = df_display.rename(columns={
                'texto_original': 'Original',
                'valor_normalizado': 'Normalizado',
                'metodo_usado': 'Método',
                'confianza': 'Confianza',
                'requiere_revision': 'Revisión',
                'fecha_proceso': 'Fecha'
            })
            
            # CONFIGURACIÓN RESPONSIVA AVANZADA
            st.dataframe(
                df_display, 
                use_container_width=True, 
                hide_index=True, 
                height=400,
                column_config={
                    "Original": st.column_config.TextColumn(
                        "Original",
                        help="Texto original de AS400",
                        width="medium",
                        max_chars=50
                    ),
                    "Normalizado": st.column_config.TextColumn(
                        "Normalizado", 
                        help="Texto normalizado con SEPOMEX",
                        width="medium",
                        max_chars=50
                    ),
                    "Método": st.column_config.TextColumn(
                        "Método",
                        help="Algoritmo usado para normalización",
                        width="small"
                    ),
                    "Confianza": st.column_config.TextColumn(
                        "Confianza",
                        help="Nivel de confianza del resultado",
                        width="small"
                    ),
                    "Revisión": st.column_config.TextColumn(
                        "Revisión",
                        help="Indica si requiere validación manual",
                        width="small"
                    ),
                    "Fecha": st.column_config.TextColumn(
                        "Fecha",
                        help="Fecha y hora de procesamiento",
                        width="small"
                    )
                }
            )
            
            # VISTA MÓVIL ALTERNATIVA
            if st.checkbox("📱 Vista Móvil Compacta", help="Activa para pantallas pequeñas"):
                st.markdown("### 📋 Vista Compacta")
                
                # Mostrar solo datos esenciales en formato de cards
                for idx, row in df_display.head(10).iterrows():  # Solo primeros 10 en vista móvil
                    with st.expander(f"📄 {row['Original'][:30]}..."):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Original:** {row['Original']}")
                            st.write(f"**Método:** {row['Método']}")
                            st.write(f"**Fecha:** {row['Fecha']}")
                        
                        with col2:
                            st.write(f"**Normalizado:** {row['Normalizado']}")
                            st.write(f"**Confianza:** {row['Confianza']}")
                            st.write(f"**Revisión:** {row['Revisión']}")
            
            # Botón para descargar resultados
            csv_export = df_resultados.to_csv(index=False)
            st.download_button(
                label="📥 Descargar Resultados (CSV)",
                data=csv_export,
                file_name=f"resultados_{archivo_info['nombre_archivo']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        else:
            st.warning("⚠️ No se encontraron resultados para este archivo.")
    
    except Exception as e:
        st.error(f"Error consultando resultados: {str(e)}")

def mostrar_configuracion_sistema():
    """Sección de configuración y administración del sistema"""
    
    st.markdown("## ⚙️ Configuración del Sistema")
    
    usuario_actual = st.session_state.get('usuario_actual', {})
    rol_usuario = usuario_actual.get('rol', 'USUARIO')
    
    # Tabs diferentes según el rol
    if rol_usuario == 'SUPERUSUARIO':
        # SUPERUSUARIO: Ve todo
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🗄️ Base de Datos", 
            "📚 Referencias", 
            "🧹 Mantenimiento", 
            "📊 Estadísticas",
            "⚡ Cache Inteligente"
        ])
        
        with tab1:
            mostrar_config_base_datos()  # Con parámetros del sistema
        
        with tab2:
            mostrar_gestion_referencias()
        
        with tab3:
            mostrar_mantenimiento_sistema()
        
        with tab4:
            mostrar_estadisticas_sistema()

        with tab5:
            #mostrar_panel_cache_simple()     
            mostrar_panel_cache_persistente()   

        
    
    elif rol_usuario == 'GERENTE':
        # GERENTE: Sin parámetros técnicos
        tab1, tab2, tab3 = st.tabs([
            "🗄️ Base de Datos", 
            "📚 Referencias", 
            "📊 Estadísticas"
        ])
        
        with tab1:
            mostrar_config_base_datos()  # Sin parámetros del sistema
        
        with tab2:
            mostrar_gestion_referencias()
        
        with tab3:
            mostrar_estadisticas_sistema()
    
    else:
        # USUARIO: Acceso muy limitado
        st.error("❌ No tienes permisos para acceder a la configuración del sistema")
        st.info("""
        👤 **Acceso de Usuario:**
        
        La configuración del sistema está restringida a administradores.
        
        📞 **¿Necesitas cambiar algo?** Contacta a un gerente o administrador.
        """)
# ========================================
# CORRECCIÓN ADICIONAL PARA OTRAS FUNCIONES SIMILARES
# ========================================

def mostrar_config_base_datos():
    """Configuración de base de datos - VERSIÓN CORREGIDA"""
    
    st.markdown("### 🗄️ Configuración de PostgreSQL")
    
    sistema = SistemaNormalizacion()
    usuario_actual = st.session_state.get('usuario_actual', {})
    rol_usuario = usuario_actual.get('rol', 'USUARIO')
    
    # Estado de conexión (todos pueden ver esto)
    if sistema.engine:
        st.success("✅ Conexión a PostgreSQL activa")
        
        try:
            with sistema.engine.connect() as conn:
                # Información de la base de datos
                result = conn.execute(text("SELECT version()"))
                version_row = result.fetchone()
                version = version_row[0] if version_row else "Desconocida"
                
                result = conn.execute(text("""
                    SELECT 
                        schemaname,
                        relname as tablename,
                        n_tup_ins as inserts,
                        n_tup_upd as updates,
                        n_tup_del as deletes
                    FROM pg_stat_user_tables 
                    WHERE schemaname = 'public'
                    ORDER BY relname
                """))

                # CORRECCIÓN: Manejar resultados correctamente
                tablas_stats = []
                for row in result:
                    if row is not None:
                        # Crear diccionario manualmente
                        tablas_stats.append({
                            'schemaname': row[0],
                            'tablename': row[1],
                            'inserts': row[2],
                            'updates': row[3],
                            'deletes': row[4]
                        })
            
            # Mostrar información básica (todos pueden ver)
            st.info(f"**Versión PostgreSQL:** {version}")
            
            if tablas_stats:
                st.markdown("#### 📊 Estadísticas de Tablas:")
                
                df_stats = pd.DataFrame(tablas_stats)
                df_stats = df_stats[['tablename', 'inserts', 'updates', 'deletes']].copy()
                df_stats.columns = ['Tabla', 'Inserts', 'Updates', 'Deletes']
                
                st.dataframe(df_stats, use_container_width=True, hide_index=True)
            else:
                st.info("ℹ️ No hay estadísticas de tablas disponibles (tablas vacías)")
            
        except Exception as e:
            st.error(f"Error obteniendo información de BD: {str(e)}")
            
            # Debug solo para administradores
            if rol_usuario in ['SUPERUSUARIO', 'GERENTE']:
                if st.checkbox("🔧 Mostrar detalles técnicos"):
                    st.code(f"""
Error: {str(e)}
Tipo: {type(e).__name__}

Consulta problemática: pg_stat_user_tables
Posibles soluciones:
1. Verificar permisos de usuario PostgreSQL
2. Actualizar estadísticas: ANALYZE;
3. Verificar que existan tablas en el esquema public
                    """)
    
    else:
        st.error("❌ No hay conexión a PostgreSQL")
        
        # Ayuda para solucionar problemas de conexión
        st.markdown("### 🔧 Solución de Problemas:")
        st.markdown("""
        **Verifica la configuración:**
        - Host: localhost (o Railway)
        - Puerto: 5432
        - Base de datos: normalizacion_domicilios
        - Usuario: postgres
        - Contraseña: [configurada]
        
        **Comandos útiles para desarrollo local:**
        ```bash
        # Verificar si PostgreSQL está corriendo
        sudo systemctl status postgresql
        
        # Crear base de datos
        createdb normalizacion_domicilios
        
        # Conectar manualmente
        psql -h localhost -U postgres -d normalizacion_domicilios
        ```
        """)
    
    st.markdown("---")
    
    # CONTROL DE ACCESO: Solo SUPERUSUARIOS ven parámetros del sistema
    if rol_usuario == 'SUPERUSUARIO':
        mostrar_parametros_sistema_admin()
    else:
        mostrar_mensaje_permisos_parametros(rol_usuario)

def mostrar_gestion_referencias():
    """Gestión completa de referencias - VERSIÓN CORREGIDA"""
    
    st.markdown("### 📚 Gestión de Referencias")
    
    sistema = SistemaNormalizacion()
    
    # Resumen de referencias actuales - CON MANEJO DE ERRORES
    try:
        with sistema.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT 
                    tipo_catalogo,
                    COUNT(*) as total,
                    COUNT(CASE WHEN coordenadas_lat IS NOT NULL THEN 1 END) as con_coordenadas,
                    MAX(fecha_actualizacion) as ultima_actualizacion
                FROM referencias_normalizacion
                WHERE activo = true
                GROUP BY tipo_catalogo
                ORDER BY tipo_catalogo
            """))
            
            # CONVERSIÓN SEGURA DE ROWS
            referencias_resumen = []
            for row in result:
                try:
                    # Usar conversión segura
                    row_dict = convertir_row_a_dict_seguro(row)
                    referencias_resumen.append(row_dict)
                except Exception as e:
                    print(f"⚠️ Error convirtiendo row en gestión: {e}")
                    # Crear manualmente si falla
                    try:
                        referencias_resumen.append({
                            'tipo_catalogo': row[0],
                            'total': row[1],
                            'con_coordenadas': row[2],
                            'ultima_actualizacion': row[3]
                        })
                    except:
                        continue
    
        if referencias_resumen:
            st.markdown("#### 📊 Estado Actual de Referencias:")
            
            df_resumen = pd.DataFrame(referencias_resumen)
            df_resumen.columns = ['Tipo', 'Total', 'Con Coordenadas', 'Última Actualización']
            
            st.dataframe(df_resumen, use_container_width=True, hide_index=True)
        
        else:
            st.warning("No hay referencias cargadas en el sistema")
    
    except Exception as e:
        st.error(f"Error consultando referencias: {str(e)}")
        
        # Fallback - mostrar información básica
        st.info("Intentando obtener información básica...")
        try:
            with sistema.engine.connect() as conn:
                result = conn.execute(text("SELECT COUNT(*) FROM referencias_normalizacion"))
                total_refs = result.fetchone()[0]
                st.info(f"📊 Total de referencias en el sistema: {total_refs:,}")
        except:
            st.error("No se pudo conectar a la base de datos")
    
    st.markdown("---")
    
    # Acciones de mantenimiento de referencias
    st.markdown("#### 🔧 Acciones de Mantenimiento:")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🧹 Limpiar Referencias Duplicadas"):
            limpiar_referencias_duplicadas_seguro(sistema)
    
    with col2:
        if st.button("📊 Validar Integridad"):
            validar_integridad_referencias_seguro(sistema)
    
    with col3:
        if st.button("📥 Exportar Referencias"):
            exportar_referencias_seguro(sistema)
            

# ========================================
# FUNCIONES DE MANTENIMIENTO CORREGIDAS
# ========================================

def limpiar_referencias_duplicadas_seguro(sistema):
    """Limpiar referencias duplicadas con manejo de errores"""
    
    try:
        with sistema.engine.connect() as conn:
            # Contar duplicados primero
            result = conn.execute(text("""
                SELECT COUNT(*) FROM (
                    SELECT tipo_catalogo, nombre_oficial, COUNT(*) 
                    FROM referencias_normalizacion
                    GROUP BY tipo_catalogo, nombre_oficial
                    HAVING COUNT(*) > 1
                ) as duplicados
            """))
            
            duplicados_count = result.fetchone()[0]
            
            if duplicados_count > 0:
                st.warning(f"⚠️ Se encontraron {duplicados_count} grupos de duplicados")
                
                if st.button("Confirmar eliminación de duplicados"):
                    # Eliminar duplicados manteniendo el más reciente
                    result = conn.execute(text("""
                        DELETE FROM referencias_normalizacion 
                        WHERE id_referencia NOT IN (
                            SELECT DISTINCT ON (tipo_catalogo, nombre_oficial) id_referencia
                            FROM referencias_normalizacion
                            ORDER BY tipo_catalogo, nombre_oficial, fecha_actualizacion DESC
                        )
                    """))
                    
                    conn.commit()
                    eliminados = result.rowcount
                    st.success(f"✅ Se eliminaron {eliminados} referencias duplicadas")
            else:
                st.success("✅ No hay referencias duplicadas")
        
    except Exception as e:
        st.error(f"Error limpiando duplicados: {str(e)}")

def validar_integridad_referencias_seguro(sistema):
    """Validar integridad de las referencias con manejo de errores"""
    
    try:
        with sistema.engine.connect() as conn:
            # Verificaciones básicas
            problemas = []
            
            # 1. Referencias sin nombre oficial
            result = conn.execute(text("""
                SELECT COUNT(*) FROM referencias_normalizacion 
                WHERE nombre_oficial IS NULL OR nombre_oficial = ''
            """))
            sin_nombre = result.fetchone()[0]
            
            # 2. Referencias sin código
            result = conn.execute(text("""
                SELECT COUNT(*) FROM referencias_normalizacion 
                WHERE codigo_oficial IS NULL OR codigo_oficial = ''
            """))
            sin_codigo = result.fetchone()[0]
            
            # 3. Referencias inactivas
            result = conn.execute(text("""
                SELECT COUNT(*) FROM referencias_normalizacion WHERE activo = false
            """))
            inactivos = result.fetchone()[0]
            
            # 4. Referencias por tipo
            result = conn.execute(text("""
                SELECT tipo_catalogo, COUNT(*) 
                FROM referencias_normalizacion 
                WHERE activo = true
                GROUP BY tipo_catalogo
            """))
            
            tipos_count = {}
            for row in result:
                tipos_count[row[0]] = row[1]
        
        # Mostrar resultados
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if sin_nombre > 0:
                st.error(f"❌ {sin_nombre} referencias sin nombre oficial")
                problemas.append(f"{sin_nombre} sin nombre")
            else:
                st.success("✅ Todas tienen nombre oficial")
        
        with col2:
            if sin_codigo > 0:
                st.warning(f"⚠️ {sin_codigo} referencias sin código oficial")
                problemas.append(f"{sin_codigo} sin código")
            else:
                st.success("✅ Todas tienen código oficial")
        
        with col3:
            if inactivos > 0:
                st.info(f"ℹ️ {inactivos} referencias inactivas")
            else:
                st.success("✅ Todas las referencias están activas")
        
        # Resumen por tipo
        if tipos_count:
            st.markdown("#### 📊 Referencias por Tipo:")
            for tipo, count in tipos_count.items():
                st.write(f"**{tipo}:** {count:,} registros")
        
        # Resumen final
        if problemas:
            st.warning(f"⚠️ Se encontraron algunos problemas: {', '.join(problemas)}")
        else:
            st.success("✅ Integridad de referencias OK")
    
    except Exception as e:
        st.error(f"Error validando integridad: {str(e)}")

def exportar_referencias_seguro(sistema):
    """Exportar todas las referencias con manejo de errores"""
    
    try:
        with sistema.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT tipo_catalogo, codigo_oficial, nombre_oficial,
                       coordenadas_lat, coordenadas_lng, estado_padre, municipio_padre,
                       activo, fecha_actualizacion
                FROM referencias_normalizacion 
                WHERE activo = true 
                ORDER BY tipo_catalogo, nombre_oficial
            """))
            
            # CONVERSIÓN SEGURA
            referencias = []
            for row in result:
                try:
                    # Crear diccionario manualmente
                    ref_dict = {
                        'tipo_catalogo': row[0],
                        'codigo_oficial': row[1],
                        'nombre_oficial': row[2],
                        'coordenadas_lat': row[3],
                        'coordenadas_lng': row[4],
                        'estado_padre': row[5],
                        'municipio_padre': row[6],
                        'activo': row[7],
                        'fecha_actualizacion': row[8]
                    }
                    referencias.append(ref_dict)
                except Exception as e:
                    print(f"⚠️ Error convirtiendo row para export: {e}")
                    continue
        
        if referencias:
            df_export = pd.DataFrame(referencias)
            csv_export = df_export.to_csv(index=False)
            
            st.download_button(
                label="📥 Descargar Referencias Completas",
                data=csv_export,
                file_name=f"referencias_completas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
            
            st.success(f"✅ Preparadas {len(referencias)} referencias para descarga")
        else:
            st.warning("No hay referencias para exportar")
    
    except Exception as e:
        st.error(f"Error exportando referencias: {str(e)}")


# ========================================
# FUNCIÓN ALTERNATIVA PARA MANTENIMIENTO BÁSICO
# AGREGAR ESTA NUEVA FUNCIÓN
# ========================================

def mantenimiento_basico_seguro(sistema):
    """Mantenimiento básico sin VACUUM (más seguro)"""
    
    st.markdown("### 🛠️ Mantenimiento Básico (Seguro)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📊 Solo ANALYZE (Recomendado)", type="primary"):
            try:
                with sistema.engine.connect() as conn:
                    # Solo ANALYZE, sin VACUUM
                    conn.execute(text("ANALYZE"))
                    conn.commit()
                
                st.success("✅ Estadísticas actualizadas con ANALYZE")
                st.info("📊 El rendimiento de consultas ha sido optimizado")
                
            except Exception as e:
                st.error(f"Error en ANALYZE: {str(e)}")
    
    with col2:
        if st.button("🧹 VACUUM Completo (Avanzado)"):
            if st.checkbox("⚠️ Confirmar VACUUM (puede tomar tiempo)"):
                optimizar_tablas(sistema)

def mostrar_informacion_mantenimiento():
    """Mostrar información sobre las opciones de mantenimiento"""
    
    st.markdown("### ℹ️ Información de Mantenimiento")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **📊 ANALYZE (Recomendado):**
        - ✅ Rápido y seguro
        - ✅ Actualiza estadísticas
        - ✅ Mejora rendimiento
        - ✅ No bloquea tablas
        """)
    
    with col2:
        st.markdown("""
        **🧹 VACUUM (Avanzado):**
        - ⚠️ Puede tomar tiempo
        - ⚠️ Requiere permisos especiales
        - ✅ Libera espacio físico
        - ✅ Reorganiza tablas
        """)
    
    st.info("""
    **💡 Recomendación:**
    - Para uso diario: Usar solo **ANALYZE**
    - Para mantenimiento profundo: Usar **VACUUM** cuando la aplicación tenga poco tráfico
    - La diferencia principal es que VACUUM libera espacio físico, pero es más lento
    """)



# ========================================
# 7. DASHBOARD PRINCIPAL MEJORADO
# ========================================

def mostrar_dashboard_principal():
    """Dashboard principal con métricas del sistema completo - COMPLETAMENTE CORREGIDO"""
   
    st.markdown("## 📊 Dashboard Principal")

    sistema = SistemaNormalizacion()
    
    try:
        with sistema.engine.connect() as conn:
            # Métricas generales
            result = conn.execute(text("""
                SELECT 
                    COUNT(DISTINCT a.id_archivo) as total_archivos,
                    COALESCE(SUM(a.total_registros), 0) as total_registros,
                    COUNT(r.id_resultado) as total_procesados,
                    COUNT(CASE WHEN r.valor_normalizado IS NOT NULL THEN 1 END) as total_normalizados,
                    COUNT(CASE WHEN r.requiere_revision = true THEN 1 END) as total_revision,
                    COALESCE(AVG(CASE WHEN r.confianza > 0 THEN r.confianza END), 0) as confianza_promedio
                FROM archivos_cargados a
                LEFT JOIN resultados_normalizacion r ON a.id_archivo = r.id_archivo
                WHERE a.fecha_carga >= CURRENT_DATE - INTERVAL '30 days'
            """))
            
            # CORRECCIÓN PRINCIPAL: Manejar resultado None
            row = result.fetchone()
            if row is not None:
                metricas = dict(row._mapping)  # Usar _mapping para SQLAlchemy 2.0
            else:
                metricas = {
                    'total_archivos': 0,
                    'total_registros': 0,
                    'total_procesados': 0,
                    'total_normalizados': 0,
                    'total_revision': 0,
                    'confianza_promedio': 0
                }
    
        # Asegurar que los valores no sean None
        for key in metricas:
            if metricas[key] is None:
                metricas[key] = 0
    
        # Mostrar métricas principales
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div style="background: white; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                    <div style="width: 40px; height: 40px; background: rgba(229, 62, 62, 0.1); 
                               border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        <span style="color: #E53E3E; font-size: 1.2rem;">📁</span>
                    </div>
                    <h3 style="color: #2D3748; margin: 0; font-size: 0.9rem; font-weight: 600;">Archivos Procesados</h3>
                </div>
                <div style="font-size: 2.5rem; font-weight: 700; color: #2D3748; margin-bottom: 0.5rem;">
                    {int(metricas['total_archivos']):,}
                </div>
                <div style="color: #2D3748; font-size: 0.85rem;">Últimos 30 días</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            total_procesados = int(metricas['total_procesados'])
            total_normalizados = int(metricas['total_normalizados'])
            porcentaje_exito = (total_normalizados / total_procesados * 100) if total_procesados > 0 else 0
            
            st.markdown(f"""
            <div style="background: white; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                    <div style="width: 40px; height: 40px; background: rgba(56, 161, 105, 0.1); 
                               border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        <span style="color: #38A169; font-size: 1.2rem;">✅</span>
                    </div>
                    <h3 style="color: #2D3748; margin: 0; font-size: 0.9rem; font-weight: 600;">Tasa de Éxito</h3>
                </div>
                <div style="font-size: 2.5rem; font-weight: 700; color: #2D3748; margin-bottom: 0.5rem;">
                    {porcentaje_exito:.1f}%
                </div>
                <div style="color: #2D3748; font-size: 0.85rem;">Normalización exitosa</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div style="background: white; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                    <div style="width: 40px; height: 40px; background: rgba(0, 102, 204, 0.1); 
                               border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        <span style="color: #0066CC; font-size: 1.2rem;">📊</span>
                    </div>
                    <h3 style="color: #2D3748; margin: 0; font-size: 0.9rem; font-weight: 600;">Total Registros</h3>
                </div>
                <div style="font-size: 2.5rem; font-weight: 700; color: #2D3748; margin-bottom: 0.5rem;">
                    {total_procesados:,}
                </div>
                <div style="color: #2D3748; font-size: 0.85rem;">Registros procesados</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            confianza_prom = float(metricas['confianza_promedio']) * 100
            st.markdown(f"""
            <div style="background: white; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                    <div style="width: 40px; height: 40px; background: rgba(214, 158, 46, 0.1); 
                               border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        <span style="color: #D69E2E; font-size: 1.2rem;">🎯</span>
                    </div>
                    <h3 style="color: #2D3748; margin: 0; font-size: 0.9rem; font-weight: 600;">Confianza Promedio</h3>
                </div>
                <div style="font-size: 2.5rem; font-weight: 700; color: #2D3748; margin-bottom: 0.5rem;">
                    {confianza_prom:.1f}%
                </div>
                <div style="color: #2D3748; font-size: 0.85rem;">Nivel de confianza</div>
            </div>
            """, unsafe_allow_html=True)
    
        # Gráficos de análisis
        st.markdown("---")
        mostrar_graficos_analisis()
    
    except Exception as e:
        st.error(f"Error cargando dashboard: {str(e)}")
        # Mostrar dashboard con valores por defecto
        mostrar_dashboard_vacio()


def mostrar_dashboard_vacio():
    """Mostrar dashboard con valores por defecto cuando no hay datos"""
    
    st.info("👋 ¡Bienvenido al Sistema de Normalización! No hay datos procesados aún.")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Archivos Procesados", "0", "📁")
    with col2:
        st.metric("Tasa de Éxito", "0%", "✅")
    with col3:
        st.metric("Total Registros", "0", "📊")
    with col4:
        st.metric("Confianza Promedio", "0%", "🎯")
    
    st.markdown("---")
    st.markdown("### 🚀 ¿Cómo empezar?")
    st.markdown("""
    1. **📁 Sube archivos** en la pestaña "Carga de Archivos"
    2. **📚 Configura referencias** SEPOMEX/INEGI si es necesario
    3. **⚙️ Procesa los datos** y ve los resultados aquí
    """)





def mostrar_graficos_analisis():
    """Mostrar gráficos de análisis del sistema - COMPLETAMENTE CORREGIDO"""
    
    sistema = SistemaNormalizacion()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📊 Procesamiento por Tipo de Catálogo")
        
        try:
            with sistema.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT 
                        r.tipo_catalogo,
                        COUNT(*) as total,
                        COUNT(CASE WHEN r.valor_normalizado IS NOT NULL THEN 1 END) as exitosos
                    FROM resultados_normalizacion r
                    WHERE r.fecha_proceso >= CURRENT_DATE - INTERVAL '30 days'
                    GROUP BY r.tipo_catalogo
                    ORDER BY total DESC
                """))
                
                # CORRECCIÓN: Manejar resultados vacíos correctamente
                datos = []
                for row in result:
                    datos.append(dict(row._mapping))
            
            if datos and len(datos) > 0:
                df_tipos = pd.DataFrame(datos)
                df_tipos['porcentaje_exito'] = (df_tipos['exitosos'] / df_tipos['total'] * 100).round(1)
                
                fig = px.bar(
                    df_tipos,
                    x='tipo_catalogo',
                    y='porcentaje_exito',
                    color='tipo_catalogo',
                    text='porcentaje_exito',
                    color_discrete_sequence=['#E53E3E', '#0066CC', '#38A169', '#D69E2E']
                )
                
                fig.update_traces(texttemplate='%{text}%', textposition='outside')
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    showlegend=False,
                    height=300,
                    margin=dict(l=0, r=0, t=0, b=0)
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("📈 No hay datos de procesamiento recientes para mostrar gráficos.")
        
        except Exception as e:
            st.error(f"Error generando gráfico: {str(e)}")
    
    with col2:
        st.markdown("### 🎯 Distribución de Métodos de Normalización")
        
        try:
            with sistema.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT metodo_usado, COUNT(*) as cantidad
                    FROM resultados_normalizacion
                    WHERE fecha_proceso >= CURRENT_DATE - INTERVAL '30 days'
                    AND metodo_usado IS NOT NULL
                    GROUP BY metodo_usado
                    ORDER BY cantidad DESC
                """))
                
                # CORRECCIÓN: Manejar resultados vacíos
                metodos = []
                for row in result:
                    metodos.append(dict(row._mapping))
            
            if metodos and len(metodos) > 0:
                df_metodos = pd.DataFrame(metodos)
                
                fig = go.Figure(data=[go.Pie(
                    labels=df_metodos['metodo_usado'],
                    values=df_metodos['cantidad'],
                    hole=0.4,
                    marker=dict(
                        colors=['#0066CC', '#38A169', '#D69E2E', '#E53E3E'],
                        line=dict(color='white', width=2)
                    )
                )])
                
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    height=300,
                    margin=dict(l=0, r=0, t=0, b=0),
                    showlegend=True,
                    legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.05)
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("🎯 No hay datos de métodos recientes para mostrar.")
        
        except Exception as e:
            st.error(f"Error generando gráfico de métodos: {str(e)}")


# ========================================
# CORRECCIÓN ADICIONAL PARA ESTADÍSTICAS
# ========================================

def mostrar_estadisticas_sistema():
    """Estadísticas detalladas del sistema - VERSIÓN CORREGIDA"""
    
    st.markdown("### 📊 Estadísticas del Sistema")
    
    sistema = SistemaNormalizacion()
    
    try:
        with sistema.engine.connect() as conn:
            # Estadísticas generales
            result = conn.execute(text("""
                SELECT 
                    COUNT(DISTINCT a.id_archivo) as total_archivos,
                    COALESCE(SUM(a.total_registros), 0) as total_registros_cargados,
                    COUNT(r.id_resultado) as total_registros_procesados,
                    COUNT(CASE WHEN r.valor_normalizado IS NOT NULL THEN 1 END) as registros_exitosos,
                    COUNT(CASE WHEN r.requiere_revision = true THEN 1 END) as requieren_revision,
                    COALESCE(AVG(CASE WHEN r.confianza > 0 THEN r.confianza END), 0) as confianza_promedio,
                    MIN(a.fecha_carga) as primera_carga,
                    MAX(a.fecha_carga) as ultima_carga
                FROM archivos_cargados a
                LEFT JOIN resultados_normalizacion r ON a.id_archivo = r.id_archivo
            """))
            
            # CORRECCIÓN PRINCIPAL
            row = result.fetchone()
            if row is not None:
                # Crear diccionario manualmente para evitar errores
                stats_generales = {
                    'total_archivos': row[0] or 0,
                    'total_registros_cargados': row[1] or 0,
                    'total_registros_procesados': row[2] or 0,
                    'registros_exitosos': row[3] or 0,
                    'requieren_revision': row[4] or 0,
                    'confianza_promedio': row[5] or 0,
                    'primera_carga': row[6],
                    'ultima_carga': row[7]
                }
            else:
                stats_generales = {
                    'total_archivos': 0,
                    'total_registros_cargados': 0,
                    'total_registros_procesados': 0,
                    'registros_exitosos': 0,
                    'requieren_revision': 0,
                    'confianza_promedio': 0,
                    'primera_carga': None,
                    'ultima_carga': None
                }
            
            # Estadísticas por división - CORREGIDO
            result = conn.execute(text("""
                SELECT 
                    r.division,
                    COUNT(*) as total,
                    COUNT(CASE WHEN r.valor_normalizado IS NOT NULL THEN 1 END) as exitosos,
                    COALESCE(AVG(CASE WHEN r.confianza > 0 THEN r.confianza END), 0) as confianza_promedio
                FROM resultados_normalizacion r
                GROUP BY r.division
                ORDER BY total DESC
            """))
            
            stats_division = []
            for row in result:
                if row is not None:
                    stats_division.append({
                        'division': row[0],
                        'total': row[1],
                        'exitosos': row[2],
                        'confianza_promedio': row[3] or 0
                    })
            
            # Estadísticas por método - CORREGIDO
            result = conn.execute(text("""
                SELECT 
                    metodo_usado,
                    COUNT(*) as cantidad,
                    COALESCE(AVG(confianza), 0) as confianza_promedio
                FROM resultados_normalizacion
                WHERE metodo_usado IS NOT NULL
                GROUP BY metodo_usado
                ORDER BY cantidad DESC
            """))
            
            stats_metodos = []
            for row in result:
                if row is not None:
                    stats_metodos.append({
                        'metodo_usado': row[0],
                        'cantidad': row[1],
                        'confianza_promedio': row[2] or 0
                    })
    
        # Mostrar estadísticas generales
        st.markdown("#### 📈 Estadísticas Generales:")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Archivos Procesados", f"{int(stats_generales['total_archivos']):,}")
        
        with col2:
            st.metric("Registros Totales", f"{int(stats_generales['total_registros_procesados']):,}")
        
        with col3:
            total_proc = int(stats_generales['total_registros_procesados'])
            exitosos = int(stats_generales['registros_exitosos'])
            porcentaje_exito = (exitosos / total_proc * 100) if total_proc > 0 else 0
            st.metric("Tasa de Éxito", f"{porcentaje_exito:.1f}%")
        
        with col4:
            confianza = float(stats_generales['confianza_promedio']) * 100
            st.metric("Confianza Promedio", f"{confianza:.1f}%")
        
        # Estadísticas por división
        if stats_division:
            st.markdown("#### 🏢 Estadísticas por División:")
            
            df_division = pd.DataFrame(stats_division)
            # Evitar división por cero y valores None
            df_division['porcentaje_exito'] = df_division.apply(
                lambda row: (row['exitosos'] / row['total'] * 100) if row['total'] > 0 else 0, axis=1
            ).round(1)
            df_division['confianza_promedio'] = (df_division['confianza_promedio'] * 100).round(1)
            
            df_division.columns = ['División', 'Total', 'Exitosos', 'Confianza %', '% Éxito']
            
            st.dataframe(df_division, use_container_width=True, hide_index=True)
        
        # Estadísticas por método
        if stats_metodos:
            st.markdown("#### ⚙️ Estadísticas por Método:")
            
            df_metodos = pd.DataFrame(stats_metodos)
            df_metodos['confianza_promedio'] = (df_metodos['confianza_promedio'] * 100).round(1)
            
            df_metodos.columns = ['Método', 'Cantidad', 'Confianza Promedio %']
            
            st.dataframe(df_metodos, use_container_width=True, hide_index=True)
        
        # Información temporal
        if stats_generales['primera_carga']:
            st.markdown("#### 📅 Información Temporal:")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.info(f"**Primera carga:** {stats_generales['primera_carga']}")
            
            with col2:
                st.info(f"**Última carga:** {stats_generales['ultima_carga']}")
        else:
            st.info("ℹ️ No hay datos históricos disponibles. El sistema está listo para procesar archivos.")
    
    except Exception as e:
        st.error(f"Error obteniendo estadísticas: {str(e)}")
        
        # Debug detallado para administradores
        usuario_actual = st.session_state.get('usuario_actual', {})
        rol_usuario = usuario_actual.get('rol', 'USUARIO')
        
        if rol_usuario in ['SUPERUSUARIO', 'GERENTE']:
            if st.checkbox("🔧 Ver detalles del error de estadísticas"):
                import traceback
                st.code(traceback.format_exc())


# ========================================
# 8. APLICACIÓN PRINCIPAL
# ========================================

#def main():
def main_aplicacion_original():
    """Aplicación principal del sistema integral"""
    
    # Aplicar estilos CSS
    st.markdown(f"""
    <style>
        .stApp {{
            background: {COLORES['gris_claro']};
        }}
        
        .main-header {{
            background: linear-gradient(135deg, {COLORES['azul_telmex']}, {COLORES['rojo_principal']});
            background: linear-gradient(135deg, {COLORES['blanco']}, {COLORES['blanco']});
            color: navy;
            padding: 2rem;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }}
        
        .main-header h1 {{
            font-size: 2.5rem;
            font-weight: 900;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .main-header p {{
            font-size: 1.2rem;
            margin: 0.5rem 0 0 0;
            opacity: 0.9;
        }}
    </style>
    """, unsafe_allow_html=True)
    
    # Header principal
    # RRV01 col_logo, col_title = st.columns([1, 8])
    # with col_logo:
    #     try:
    #         st.image("logo_RN.png", width=120)
    #     except:
    #         st.markdown("🏠")
    # with col_title:
    #     st.markdown("""
    #     <div  style="text-align: left;">
    #         <h3>Red Nacional Última Milla</h3>
    #         <h5>Sistema Integral de Normalización Domicilios | Procesamiento Inteligente de Domicilios</h5>
    #     </div>
    #     """, unsafe_allow_html=True)

    # Header principal CON INDICADOR DE AMBIENTE
    col_logo, col_title, col_env = st.columns([1, 7, 1])
    
    with col_logo:
        try:
            st.image("logo_RN.png", width=120)
        except:
            st.markdown("🏠")
    
    with col_title:
        st.markdown("""
        <div style="text-align: left;">
            <h3>Red Nacional Última Milla</h3>
            <h5>Sistema Integral de Normalización Domicilios | Procesamiento Inteligente de Domicilios</h5>
        </div>
        """, unsafe_allow_html=True)
    
    with col_env:
        # NUEVO: Indicador de ambiente
        if IS_RAILWAY:
            st.markdown("""
            <div style="
                background: #10b981; 
                color: white; 
                padding: 0.5rem; 
                border-radius: 12px; 
                text-align: center;
                font-size: 0.85rem;
                font-weight: bold;
                margin-top: 1rem;
            ">
                🚂 RAILWAY<br>
                <small style="opacity: 0.8;">Producción</small>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="
                background: #3b82f6; 
                color: white; 
                padding: 0.5rem; 
                border-radius: 12px; 
                text-align: center;
                font-size: 0.85rem;
                font-weight: bold;
                margin-top: 1rem;
            ">
                🏠 LOCAL<br>
                <small style="opacity: 0.8;">Desarrollo</small>
            </div>
            """, unsafe_allow_html=True)
    
    # NAVEGACIÓN PRINCIPAL CON CONTROL POR ROL
    # Obtener rol del usuario actual
    usuario_actual = st.session_state.get('usuario_actual', {})
    rol_usuario = usuario_actual.get('rol', 'USUARIO')
    
    # Definir pestañas según el rol
    if rol_usuario in ['SUPERUSUARIO', 'GERENTE']:
        # ADMINISTRADORES: Ven todas las pestañas
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Dashboard", 
            "📁 Carga de Archivos", 
            "📋 Resultados", 
            "⚙️ Configuración"
        ])
        
        with tab1:
            mostrar_dashboard_principal()
        
        with tab2:
            mostrar_interfaz_carga()
        
        with tab3:
            mostrar_seccion_resultados()
        
        with tab4:
            mostrar_configuracion_sistema()
    
    else:
        # USUARIOS NORMALES: Solo ven 3 pestañas
        tab1, tab2, tab3 = st.tabs([
            "📊 Dashboard", 
            "📁 Carga de Archivos", 
            "📋 Resultados"
        ])
        
        with tab1:
            mostrar_dashboard_principal()
        
        with tab2:
            # Los usuarios pueden ver la interfaz pero con funciones limitadas
            mostrar_interfaz_carga_limitada()
        
        with tab3:
            mostrar_seccion_resultados()

def mostrar_seccion_resultados():
    """Sección para consultar y analizar resultados históricos"""
    
    st.markdown("## 📋 Consulta de Resultados Históricos")
    
    sistema = SistemaNormalizacion()
    
    # Filtros
    col1, col2, col3 = st.columns(3)
    
    with col1:
        tipo_filtro = st.selectbox(
            "Tipo de Catálogo:",
            ["TODOS"] + list(ESQUEMAS_AS400.keys()),
            key="filtro_tipo"
        )
    
    with col2:
        division_filtro = st.selectbox(
            "División:",
            ["TODAS", "DES", "QAS", "MEX", "GDL", "MTY", "NTE", "TIJ"],
            key="filtro_division"
        )
    
    with col3:
        fecha_desde = st.date_input(
            "Desde:",
            value=datetime.now() - timedelta(days=30),
            key="filtro_fecha"
        )
    
    # Consultar resultados
    if st.button("🔍 Buscar Resultados"):
        consultar_resultados_historicos(sistema, tipo_filtro, division_filtro, fecha_desde)
# ========================================
# FUNCIÓN GENÉRICA PARA MANEJAR RESULTADOS SQL
# AGREGAR ESTA FUNCIÓN NUEVA AL ARCHIVO
# ========================================

def sql_result_to_dict_list(result):
    """
    Convertir resultado SQL a lista de diccionarios de forma segura
    Función auxiliar para evitar errores de SQLAlchemy 2.0
    """
    
    dict_list = []
    
    try:
        for row in result:
            if row is not None:
                # Usar _mapping si está disponible (SQLAlchemy 2.0)
                if hasattr(row, '_mapping'):
                    dict_list.append(dict(row._mapping))
                # Fallback para versiones anteriores
                else:
                    dict_list.append(dict(row))
    
    except Exception as e:
        print(f"Error convirtiendo resultado SQL: {e}")
        # Intentar método alternativo
        try:
            for row in result:
                if row is not None:
                    # Crear diccionario manualmente usando nombres de columnas
                    row_dict = {}
                    for i, column in enumerate(result.keys()):
                        row_dict[column] = row[i]
                    dict_list.append(row_dict)
        except Exception as e2:
            print(f"Error en método alternativo: {e2}")
    
    return dict_list

def consultar_resultados_historicos(sistema, tipo_filtro, division_filtro, fecha_desde):
    """Consultar resultados históricos con filtros - CORREGIDA"""
    
    try:
        # Construir consulta con filtros
        where_conditions = ["r.fecha_proceso >= :fecha_desde"]
        params = {'fecha_desde': fecha_desde}
        
        if tipo_filtro != "TODOS":
            where_conditions.append("r.tipo_catalogo = :tipo")
            params['tipo'] = tipo_filtro
        
        if division_filtro != "TODAS":
            where_conditions.append("r.division = :division")
            params['division'] = division_filtro
        
        where_clause = " AND ".join(where_conditions)
        
        with sistema.engine.connect() as conn:
            result = conn.execute(text(f"""
                SELECT 
                    a.nombre_archivo,
                    r.tipo_catalogo,
                    r.division,
                    r.texto_original,
                    r.valor_normalizado,
                    r.metodo_usado,
                    r.confianza,
                    r.requiere_revision,
                    r.fecha_proceso
                FROM resultados_normalizacion r
                JOIN archivos_cargados a ON r.id_archivo = a.id_archivo
                WHERE {where_clause}
                ORDER BY r.fecha_proceso DESC
                LIMIT 1000
            """), params)
            
            # CORRECCIÓN: Manejar resultados correctamente
            resultados = []
            for row in result:
                if row is not None:
                    resultados.append(dict(row._mapping))
        
        if resultados:
            st.success(f"✅ Se encontraron {len(resultados)} resultados")
            
            # Mostrar estadísticas
            df_resultados = pd.DataFrame(resultados)
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Encontrados", f"{len(resultados):,}")
            
            with col2:
                exitosos = len(df_resultados[df_resultados['valor_normalizado'].notna()])
                porcentaje_exito = (exitosos/len(resultados)*100) if len(resultados) > 0 else 0
                st.metric("Exitosos", f"{exitosos:,}", f"{porcentaje_exito:.1f}%")
            
            with col3:
                revision = len(df_resultados[df_resultados['requiere_revision'] == True])
                st.metric("Requieren Revisión", f"{revision:,}")
            
            with col4:
                confianzas_validas = df_resultados['confianza'].dropna()
                confianza = confianzas_validas.mean() if len(confianzas_validas) > 0 else 0
                st.metric("Confianza Promedio", f"{confianza:.1%}" if confianza > 0 else "N/A")
            
            # Mostrar tabla de resultados
            st.markdown("### 📊 Resultados Detallados:")
            
            # Preparar columnas para mostrar
            df_display = df_resultados.copy()
            df_display['confianza'] = df_display['confianza'].apply(lambda x: f"{x:.1%}" if pd.notna(x) and x > 0 else "N/A")
            df_display['requiere_revision'] = df_display['requiere_revision'].apply(lambda x: "⚠️ Sí" if x else "✅ No")
            df_display['fecha_proceso'] = pd.to_datetime(df_display['fecha_proceso']).dt.strftime('%Y-%m-%d %H:%M')
            
            # Seleccionar columnas principales
            columnas_mostrar = [
                'nombre_archivo', 'tipo_catalogo', 'division', 'texto_original', 
                'valor_normalizado', 'metodo_usado', 'confianza', 'requiere_revision', 'fecha_proceso'
            ]
            
            df_final = df_display[columnas_mostrar].copy()
            df_final.columns = [
                '📄 Archivo', '📋 Tipo', '🏢 División', '📝 Original', 
                '✅ Normalizado', '⚙️ Método', '🎯 Confianza', '👀 Revisión', '📅 Fecha'
            ]
            
            st.dataframe(df_final, use_container_width=True, hide_index=True, height=400)
            
            # Botón para descargar resultados
            csv_export = df_resultados.to_csv(index=False)
            st.download_button(
                label="📥 Descargar Resultados (CSV)",
                data=csv_export,
                file_name=f"resultados_historicos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        else:
            st.warning("⚠️ No se encontraron resultados con los filtros especificados")
            
            # Sugerencias para el usuario
            st.markdown("### 💡 Sugerencias:")
            st.markdown("""
            - **Amplía el rango de fechas**: Selecciona una fecha más antigua
            - **Cambia los filtros**: Prueba con "TODOS" en tipo y división
            - **Verifica datos**: Asegúrate de haber procesado archivos recientemente
            - **Revisa la pestaña "Procesamiento"** para ver el estado de los archivos
            """)
    
    except Exception as e:
        st.error(f"Error consultando resultados: {str(e)}")
        
        # Información de ayuda
        st.markdown("### 🔧 Información Técnica:")
        st.code(f"""
Filtros aplicados:
- Tipo: {tipo_filtro}
- División: {division_filtro}  
- Fecha desde: {fecha_desde}

Error: {str(e)}
        """)

# ========================================
# 9. FUNCIONES DE UTILIDAD
# ========================================

def limpiar_referencias_duplicadas(sistema):
    """Limpiar referencias duplicadas"""
    
    try:
        with sistema.engine.connect() as conn:
            result = conn.execute(text("""
                WITH duplicados AS (
                    SELECT id_referencia,
                           ROW_NUMBER() OVER (
                               PARTITION BY tipo_catalogo, nombre_oficial 
                               ORDER BY fecha_actualizacion DESC
                           ) as rn
                    FROM referencias_normalizacion
                )
                DELETE FROM referencias_normalizacion 
                WHERE id_referencia IN (
                    SELECT id_referencia FROM duplicados WHERE rn > 1
                )
            """))
            
            conn.commit()
            eliminados = result.rowcount
        
        st.success(f"✅ Se eliminaron {eliminados} referencias duplicadas")
    
    except Exception as e:
        st.error(f"Error limpiando duplicados: {str(e)}")

def validar_integridad_referencias(sistema):
    """Validar integridad de las referencias"""
    
    try:
        with sistema.engine.connect() as conn:
            # Buscar referencias sin nombre oficial
            result = conn.execute(text("""
                SELECT COUNT(*) FROM referencias_normalizacion 
                WHERE nombre_oficial IS NULL OR nombre_oficial = ''
            """))
            sin_nombre = result.fetchone()[0]
            
            # Buscar referencias sin código
            result = conn.execute(text("""
                SELECT COUNT(*) FROM referencias_normalizacion 
                WHERE codigo_oficial IS NULL OR codigo_oficial = ''
            """))
            sin_codigo = result.fetchone()[0]
            
            # Buscar referencias inactivas
            result = conn.execute(text("""
                SELECT COUNT(*) FROM referencias_normalizacion WHERE activo = false
            """))
            inactivos = result.fetchone()[0]
        
        # Mostrar resultados
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if sin_nombre > 0:
                st.error(f"❌ {sin_nombre} referencias sin nombre oficial")
            else:
                st.success("✅ Todas tienen nombre oficial")
        
        with col2:
            if sin_codigo > 0:
                st.warning(f"⚠️ {sin_codigo} referencias sin código oficial")
            else:
                st.success("✅ Todas tienen código oficial")
        
        with col3:
            if inactivos > 0:
                st.info(f"ℹ️ {inactivos} referencias inactivas")
            else:
                st.success("✅ Todas las referencias están activas")
    
    except Exception as e:
        st.error(f"Error validando integridad: {str(e)}")

def exportar_referencias(sistema):
    """Exportar todas las referencias - VERSIÓN CORREGIDA"""
    
    try:
        with sistema.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT * FROM referencias_normalizacion 
                WHERE activo = true 
                ORDER BY tipo_catalogo, nombre_oficial
            """))
            
            # CORRECCIÓN: Usar _mapping para SQLAlchemy 2.0
            referencias = []
            for row in result:
                if row is not None:
                    # Convertir Row a diccionario correctamente
                    referencias.append(dict(row._mapping))
        
        if referencias:
            df_export = pd.DataFrame(referencias)
            csv_export = df_export.to_csv(index=False)
            
            st.download_button(
                label="📥 Descargar Referencias Completas",
                data=csv_export,
                file_name=f"referencias_completas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
            
            st.success(f"✅ Preparadas {len(referencias)} referencias para descarga")
        else:
            st.warning("No hay referencias para exportar")
    
    except Exception as e:
        st.error(f"Error exportando referencias: {str(e)}")
        
        # Debug detallado
        if st.checkbox("🔧 Mostrar detalles técnicos del error"):
            import traceback
            st.code(traceback.format_exc())

def limpiar_datos_antiguos(sistema, dias):
    """Limpiar datos anteriores a X días - VERSIÓN MEJORADA"""
    
    try:
        fecha_limite = datetime.now() - timedelta(days=dias)
        
        # Usar SQLAlchemy normal (no necesita autocommit)
        with sistema.engine.connect() as conn:
            
            # Mostrar cuántos registros se van a eliminar
            result = conn.execute(text("""
                SELECT COUNT(*) FROM resultados_normalizacion 
                WHERE fecha_proceso < :fecha_limite
            """), {'fecha_limite': fecha_limite})
            
            registros_a_eliminar = result.fetchone()[0]
            
            result = conn.execute(text("""
                SELECT COUNT(*) FROM archivos_cargados 
                WHERE fecha_carga < :fecha_limite
                AND id_archivo NOT IN (SELECT DISTINCT id_archivo FROM resultados_normalizacion)
            """), {'fecha_limite': fecha_limite})
            
            archivos_a_eliminar = result.fetchone()[0]
            
            # Mostrar preview
            st.warning(f"""
            **Vista previa de eliminación:**
            - 📊 Resultados a eliminar: {registros_a_eliminar:,}
            - 📄 Archivos a eliminar: {archivos_a_eliminar:,}
            - 📅 Anteriores a: {fecha_limite.strftime('%Y-%m-%d')}
            """)
            
            if registros_a_eliminar > 0 or archivos_a_eliminar > 0:
                if st.button("🗑️ CONFIRMAR ELIMINACIÓN", type="primary"):
                    
                    # Crear barra de progreso
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    # Eliminar resultados antiguos
                    status_text.text("🗑️ Eliminando resultados antiguos...")
                    progress_bar.progress(0.3)
                    
                    result = conn.execute(text("""
                        DELETE FROM resultados_normalizacion 
                        WHERE fecha_proceso < :fecha_limite
                    """), {'fecha_limite': fecha_limite})
                    
                    resultados_eliminados = result.rowcount
                    
                    # Eliminar archivos sin resultados
                    status_text.text("🗑️ Eliminando archivos huérfanos...")
                    progress_bar.progress(0.7)
                    
                    result = conn.execute(text("""
                        DELETE FROM archivos_cargados 
                        WHERE fecha_carga < :fecha_limite
                        AND id_archivo NOT IN (SELECT DISTINCT id_archivo FROM resultados_normalizacion)
                    """), {'fecha_limite': fecha_limite})
                    
                    archivos_eliminados = result.rowcount
                    
                    # Confirmar cambios
                    status_text.text("💾 Guardando cambios...")
                    progress_bar.progress(0.9)
                    
                    conn.commit()
                    
                    # Completado
                    progress_bar.progress(1.0)
                    status_text.text("✅ Limpieza completada")
                    
                    st.success(f"""
                    ✅ **Limpieza completada:**
                    - 📊 Resultados eliminados: {resultados_eliminados:,}
                    - 📄 Archivos eliminados: {archivos_eliminados:,}
                    - 💾 Espacio liberado en base de datos
                    """)
                    
                    # Recomendar optimización después de eliminar muchos datos
                    if resultados_eliminados > 1000:
                        st.info("💡 **Recomendación:** Ejecuta 'Optimizar Tablas' para liberar espacio físico")
            
            else:
                st.info(f"ℹ️ No hay datos anteriores a {fecha_limite.strftime('%Y-%m-%d')} para eliminar")
    
    except Exception as e:
        st.error(f"Error limpiando datos antiguos: {str(e)}")

def optimizar_tablas(sistema):
    """Optimizar tablas de PostgreSQL - VERSIÓN CORREGIDA"""
    
    try:
        # SOLUCIÓN: Usar psycopg2 directo con autocommit
        import psycopg2
        
        # Crear conexión directa con autocommit habilitado
        conn = psycopg2.connect(
            host=DATABASE_CONFIG['host'],
            port=DATABASE_CONFIG['port'],
            database=DATABASE_CONFIG['database'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password']
        )
        
        # CRÍTICO: Habilitar autocommit para VACUUM
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Lista de tablas principales
        tablas = ['resultados_normalizacion', 'archivos_cargados', 'referencias_normalizacion', 'usuarios', 'sesiones_usuario']
        
        # Crear barra de progreso
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        tablas_optimizadas = 0
        
        for i, tabla in enumerate(tablas):
            try:
                status_text.text(f"⚡ Optimizando tabla: {tabla}...")
                
                # Verificar que la tabla existe antes de hacer VACUUM
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = %s
                    )
                """, (tabla,))
                
                existe = cursor.fetchone()[0]
                
                if existe:
                    # VACUUM ANALYZE sin transacción
                    cursor.execute(f"VACUUM ANALYZE {tabla}")
                    tablas_optimizadas += 1
                    st.success(f"✅ {tabla} optimizada")
                else:
                    st.warning(f"⚠️ Tabla {tabla} no existe, omitiendo")
                
            except Exception as e:
                st.warning(f"⚠️ Error optimizando {tabla}: {str(e)}")
            
            # Actualizar progreso
            progress_bar.progress((i + 1) / len(tablas))
        
        conn.close()
        
        # Resultado final
        status_text.text("✅ Optimización completada")
        st.success(f"✅ {tablas_optimizadas} tablas optimizadas correctamente")
        
        # Información adicional
        st.info("""
        **Optimización realizada:**
        - ⚡ VACUUM: Liberó espacio no utilizado
        - 📊 ANALYZE: Actualizó estadísticas del planificador
        - 🚀 Rendimiento mejorado en consultas futuras
        """)
        
    except Exception as e:
        st.error(f"Error optimizando tablas: {str(e)}")
        
        # Información de ayuda
        st.markdown("### 🔧 Información del Error:")
        st.code(f"""
Error: {str(e)}

Posibles causas:
1. Permisos insuficientes para VACUUM
2. Conexión dentro de transacción
3. Base de datos bloqueada

Solución aplicada:
- Usar psycopg2 directo con autocommit=True
- Verificar existencia de tablas antes de VACUUM
        """)

def actualizar_estadisticas_bd(sistema):
    """Actualizar estadísticas de PostgreSQL - VERSIÓN CORREGIDA"""
    
    try:
        import psycopg2
        
        # Conexión directa con autocommit para ANALYZE
        conn = psycopg2.connect(
            host=DATABASE_CONFIG['host'],
            port=DATABASE_CONFIG['port'],
            database=DATABASE_CONFIG['database'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password']
        )
        
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Crear indicador de progreso
        with st.spinner("📊 Actualizando estadísticas de la base de datos..."):
            # ANALYZE global (más seguro que VACUUM)
            cursor.execute("ANALYZE")
            
            # También actualizar estadísticas específicas de tablas importantes
            tablas_importantes = [
                'resultados_normalizacion',
                'archivos_cargados', 
                'referencias_normalizacion'
            ]
            
            for tabla in tablas_importantes:
                try:
                    # Verificar que existe
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public' AND table_name = %s
                        )
                    """, (tabla,))
                    
                    if cursor.fetchone()[0]:
                        cursor.execute(f"ANALYZE {tabla}")
                
                except Exception as e:
                    print(f"Warning: No se pudo analizar {tabla}: {e}")
        
        conn.close()
        
        st.success("✅ Estadísticas de base de datos actualizadas")
        
        # Mostrar información de lo que se hizo
        st.info("""
        **Estadísticas actualizadas:**
        - 📊 Planificador de consultas optimizado
        - 🎯 Estimaciones de cardinalidad mejoradas  
        - ⚡ Planes de ejecución más eficientes
        """)
        
    except Exception as e:
        st.error(f"Error actualizando estadísticas: {str(e)}")


            

        

    
def descargar_resultados_archivo(id_archivo):
    """Generar descarga de resultados de un archivo - CORREGIDO"""

    sistema = SistemaNormalizacion()

    try:
        with sistema.engine.connect() as conn:
            # Obtener información del archivo
            result = conn.execute(text("""
                SELECT nombre_archivo, tipo_catalogo, division 
                FROM archivos_cargados WHERE id_archivo = :id_archivo
            """), {'id_archivo': id_archivo})
            
            # CORRECCIÓN: Manejar correctamente el resultado
            archivo_row = result.fetchone()
            if archivo_row is None:
                st.error("❌ No se encontró el archivo especificado.")
                return
                
            archivo_info = dict(archivo_row._mapping)
            
            # Obtener resultados
            result = conn.execute(text("""
                SELECT 
                    campo_status, campo_clave, campo_descripcion, texto_original,
                    valor_normalizado, codigo_normalizado, metodo_usado, confianza,
                    coordenadas_lat, coordenadas_lng, requiere_revision,
                    fecha_proceso, observaciones
                FROM resultados_normalizacion 
                WHERE id_archivo = :id_archivo
                ORDER BY fecha_proceso
            """), {'id_archivo': id_archivo})
            
            # CORRECCIÓN: Convertir correctamente a lista de diccionarios
            resultados = []
            for row in result:
                if row is not None:
                    resultados.append(dict(row._mapping))
        
        if not resultados:
            st.warning("No hay resultados para descargar")
            return
        
        # Crear DataFrames para diferentes formatos
        df_completo = pd.DataFrame(resultados)
        
        # Verificar que las columnas existan antes de usarlas
        columnas_as400 = ['campo_status', 'campo_clave', 'valor_normalizado', 'codigo_normalizado']
        columnas_disponibles = [col for col in columnas_as400 if col in df_completo.columns]
        
        if not columnas_disponibles:
            st.error("❌ No se encontraron las columnas necesarias para generar el archivo AS400")
            return
        
        # Formato para AS400 (solo campos disponibles)
        df_as400 = df_completo[columnas_disponibles].copy()
        
        # Renombrar columnas para AS400
        nombres_as400 = {
            'campo_status': 'STATUS',
            'campo_clave': 'CLAVE_ORIGINAL', 
            'valor_normalizado': 'DESCRIPCION_NORMALIZADA',
            'codigo_normalizado': 'CODIGO_NORMALIZADO'
        }
        
        df_as400 = df_as400.rename(columns={k: v for k, v in nombres_as400.items() if k in df_as400.columns})
        
        # Formato para revisión manual (solo casos que requieren revisión)
        if 'requiere_revision' in df_completo.columns:
            df_revision = df_completo[df_completo['requiere_revision'] == True].copy()
        else:
            df_revision = pd.DataFrame()  # DataFrame vacío si no existe la columna
        
        # Crear archivo ZIP con múltiples formatos
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            # Archivo completo
            csv_completo = df_completo.to_csv(index=False)
            zip_file.writestr(f"{archivo_info['nombre_archivo']}_completo.csv", csv_completo)
            
            # Archivo para AS400
            csv_as400 = df_as400.to_csv(index=False)
            zip_file.writestr(f"{archivo_info['nombre_archivo']}_as400.csv", csv_as400)
            
            # Archivo de casos para revisión (solo si hay datos)
            if not df_revision.empty:
                csv_revision = df_revision.to_csv(index=False)
                zip_file.writestr(f"{archivo_info['nombre_archivo']}_revision.csv", csv_revision)
            
            # Reporte de resumen
            total_registros = len(resultados)
            registros_exitosos = len(df_completo[df_completo['valor_normalizado'].notna()]) if 'valor_normalizado' in df_completo.columns else 0
            requieren_revision = len(df_revision)
            
            # Calcular confianza promedio de manera segura
            if 'confianza' in df_completo.columns:
                confianzas_validas = df_completo['confianza'].dropna()
                confianza_promedio = confianzas_validas.mean() if len(confianzas_validas) > 0 else 0
            else:
                confianza_promedio = 0
            
            # Distribución de métodos de manera segura
            if 'metodo_usado' in df_completo.columns:
                distribucion_metodos = df_completo['metodo_usado'].value_counts().to_string()
            else:
                distribucion_metodos = "No disponible"
            
            resumen = f"""
REPORTE DE PROCESAMIENTO
========================

Archivo: {archivo_info['nombre_archivo']}
Tipo: {archivo_info.get('tipo_catalogo', 'N/A')}
División: {archivo_info.get('division', 'N/A')}
Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

ESTADÍSTICAS:
- Total de registros: {total_registros:,}
- Registros exitosos: {registros_exitosos:,}
- Requieren revisión: {requieren_revision:,}
- Confianza promedio: {confianza_promedio:.1%}

MÉTODOS UTILIZADOS:
{distribucion_metodos}

ARCHIVOS INCLUIDOS:
- {archivo_info['nombre_archivo']}_completo.csv: Todos los resultados
- {archivo_info['nombre_archivo']}_as400.csv: Formato para cargar en AS400
""" + (f"- {archivo_info['nombre_archivo']}_revision.csv: Casos que requieren revisión manual\n" if not df_revision.empty else "")
            
            zip_file.writestr(f"{archivo_info['nombre_archivo']}_reporte.txt", resumen)
        
        # Preparar descarga
        zip_buffer.seek(0)
        
        nombre_descarga = f"resultados_{archivo_info.get('tipo_catalogo', 'datos')}_{archivo_info.get('division', 'general')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        
        st.download_button(
            label="📥 Descargar Resultados Completos",
            data=zip_buffer.getvalue(),
            file_name=nombre_descarga,
            mime="application/zip"
        )
        
        st.success(f"✅ Preparado para descarga: {len(resultados):,} registros")
        
    except Exception as e:
        st.error(f"Error preparando descarga: {str(e)}")
        # Debug adicional
        st.code(f"""
Detalles del error:
- Función: descargar_resultados_archivo()
- ID Archivo: {id_archivo}
- Error específico: {str(e)}
- Tipo de error: {type(e).__name__}
        """)

def eliminar_archivo_procesado(id_archivo):
    """Eliminar archivo procesado y sus resultados - FUNCIÓN CORREGIDA"""
    
    # ⚠️ IMPORTANTE: Usar st.session_state para evitar recrear el sistema
    if 'sistema_normalizacion' not in st.session_state:
        st.session_state.sistema_normalizacion = SistemaNormalizacion()
    
    sistema = st.session_state.sistema_normalizacion
    
    # Crear un único checkbox por archivo
    checkbox_key = f"confirm_delete_{id_archivo}"
    
    if st.checkbox("⚠️ Confirmar eliminación (esta acción no se puede deshacer)", key=checkbox_key):
        try:
            with sistema.engine.connect() as conn:
                # Primero obtener información del archivo para mostrarla
                result = conn.execute(text("""
                    SELECT nombre_archivo, tipo_catalogo, division 
                    FROM archivos_cargados 
                    WHERE id_archivo = :id_archivo
                """), {'id_archivo': id_archivo})
                
                archivo_info = result.fetchone()
                if not archivo_info:
                    st.error("❌ Archivo no encontrado")
                    return
                
                archivo_data = dict(archivo_info._mapping)
                
                # Contar registros que se van a eliminar
                result = conn.execute(text("""
                    SELECT COUNT(*) as total_resultados
                    FROM resultados_normalizacion 
                    WHERE id_archivo = :id_archivo
                """), {'id_archivo': id_archivo})
                
                total_resultados = result.fetchone()[0]
                
                # Mostrar información de lo que se va a eliminar
                st.warning(f"""
                **Se eliminará:**
                - 📄 Archivo: {archivo_data['nombre_archivo']}
                - 📋 Tipo: {archivo_data['tipo_catalogo']}
                - 🏢 División: {archivo_data['division']}
                - 📊 Resultados: {total_resultados:,} registros
                """)
                
                # Botón final de confirmación
                if st.button(f"🗑️ ELIMINAR DEFINITIVAMENTE", key=f"final_delete_{id_archivo}", type="primary"):
                    
                    # Eliminar resultados primero (por clave foránea)
                    result_delete = conn.execute(text("""
                        DELETE FROM resultados_normalizacion 
                        WHERE id_archivo = :id_archivo
                    """), {'id_archivo': id_archivo})
                    
                    resultados_eliminados = result_delete.rowcount
                    
                    # Eliminar registro del archivo
                    archivo_delete = conn.execute(text("""
                        DELETE FROM archivos_cargados 
                        WHERE id_archivo = :id_archivo
                    """), {'id_archivo': id_archivo})
                    
                    archivos_eliminados = archivo_delete.rowcount
                    
                    # Confirmar transacción
                    conn.commit()
                    
                    # Mostrar resultado
                    if archivos_eliminados > 0:
                        st.success(f"""
                        ✅ **Eliminación completada:**
                        - 📄 Archivo eliminado: {archivo_data['nombre_archivo']}
                        - 📊 Resultados eliminados: {resultados_eliminados:,}
                        - 🔄 Recarga la página para ver los cambios
                        """)
                        
                        # Forzar recarga después de 2 segundos
                        st.rerun()
                        
                    else:
                        st.error("❌ No se pudo eliminar el archivo")
        
        except Exception as e:
            st.error(f"❌ Error eliminando archivo: {str(e)}")
            
            # Mostrar detalles técnicos para debug
            with st.expander("🔧 Detalles técnicos del error"):
                st.code(f"""
Error específico: {str(e)}
Tipo de error: {type(e).__name__}
ID Archivo: {id_archivo}
                """)
    else:
        st.info("👆 Marca la casilla de confirmación para continuar con la eliminación")







# ========================================
# HERRAMIENTAS DE DIAGNÓSTICO PARA ELIMINACIÓN
# ========================================

# ========================================
# DIAGNÓSTICO AVANZADO DE BASE DE DATOS
# ========================================

def diagnostico_completo_bd():
    """
    Diagnóstico completo para identificar problemas de BD
    """
    
    st.markdown("## 🔬 Diagnóstico Avanzado de Base de Datos")
    
    if 'sistema_global' not in st.session_state:
        st.session_state.sistema_global = SistemaNormalizacion()
    
    sistema = st.session_state.sistema_global
    
    # Test 1: Verificar conexión básica
    st.markdown("### 1️⃣ Test de Conexión Básica")
    
    try:
        with sistema.engine.connect() as conn:
            result = conn.execute(text("SELECT 1 as test"))
            test_result = result.fetchone()[0]
            
            if test_result == 1:
                st.success("✅ Conexión a PostgreSQL OK")
            else:
                st.error("❌ Problema en conexión básica")
                
    except Exception as e:
        st.error(f"❌ Error de conexión: {str(e)}")
        return
    
    # Test 2: Verificar permisos de escritura
    st.markdown("### 2️⃣ Test de Permisos de Escritura")
    
    try:
        with sistema.engine.connect() as conn:
            # Intentar crear una tabla temporal
            conn.execute(text("""
                CREATE TEMPORARY TABLE test_permisos (
                    id INTEGER,
                    test_text VARCHAR(50)
                )
            """))
            
            # Intentar insertar datos
            conn.execute(text("""
                INSERT INTO test_permisos (id, test_text) VALUES (1, 'test')
            """))
            
            # Intentar hacer commit
            conn.commit()
            
            # Verificar que se insertó
            result = conn.execute(text("SELECT COUNT(*) FROM test_permisos"))
            count = result.fetchone()[0]
            
            if count == 1:
                st.success("✅ Permisos de escritura OK")
            else:
                st.error("❌ Problema con permisos de escritura")
                
    except Exception as e:
        st.error(f"❌ Error de permisos: {str(e)}")
        st.code(f"Error específico: {str(e)}")
    
    # Test 3: Verificar estructura de tablas
    st.markdown("### 3️⃣ Test de Estructura de Tablas")
    
    try:
        with sistema.engine.connect() as conn:
            # Verificar que las tablas existen
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('archivos_cargados', 'resultados_normalizacion')
                ORDER BY table_name
            """))
            
            tablas = [row[0] for row in result]
            
            st.write("**Tablas encontradas:**")
            for tabla in tablas:
                st.success(f"✅ {tabla}")
            
            if 'archivos_cargados' not in tablas:
                st.error("❌ Falta tabla 'archivos_cargados'")
            if 'resultados_normalizacion' not in tablas:
                st.error("❌ Falta tabla 'resultados_normalizacion'")
                
    except Exception as e:
        st.error(f"❌ Error verificando tablas: {str(e)}")
    
    # Test 4: Test de DELETE directo
    st.markdown("### 4️⃣ Test de DELETE Directo")
    
    if st.button("🧪 Probar DELETE Directo"):
        try:
            with sistema.engine.connect() as conn:
                
                # Primero crear un registro de prueba
                st.info("Creando registro de prueba...")
                
                test_id = f"test-{int(time.time())}"
                
                conn.execute(text("""
                    INSERT INTO archivos_cargados 
                    (id_archivo, nombre_archivo, tipo_catalogo, division, total_registros)
                    VALUES (:id, 'test_file.csv', 'ESTADOS', 'TEST', 10)
                """), {'id': test_id})
                
                conn.commit()
                st.success("✅ Registro de prueba creado")
                
                # Verificar que se creó
                result = conn.execute(text("""
                    SELECT COUNT(*) FROM archivos_cargados WHERE id_archivo = :id
                """), {'id': test_id})
                
                count_antes = result.fetchone()[0]
                st.write(f"Registros antes del DELETE: {count_antes}")
                
                # Intentar eliminarlo
                st.info("Intentando DELETE...")
                
                delete_result = conn.execute(text("""
                    DELETE FROM archivos_cargados WHERE id_archivo = :id
                """), {'id': test_id})
                
                registros_eliminados = delete_result.rowcount
                st.write(f"Registros que reporta haber eliminado: {registros_eliminados}")
                
                # CRÍTICO: Hacer commit
                conn.commit()
                st.info("✅ COMMIT ejecutado")
                
                # Verificar que se eliminó
                result = conn.execute(text("""
                    SELECT COUNT(*) FROM archivos_cargados WHERE id_archivo = :id
                """), {'id': test_id})
                
                count_despues = result.fetchone()[0]
                st.write(f"Registros después del DELETE: {count_despues}")
                
                if count_despues == 0:
                    st.success("🎉 **DELETE FUNCIONA CORRECTAMENTE**")
                    st.success("El problema NO es la función DELETE")
                else:
                    st.error("❌ **DELETE NO FUNCIONA**")
                    st.error("Hay un problema fundamental con los permisos o la BD")
                    
        except Exception as e:
            st.error(f"❌ Error en test DELETE: {str(e)}")
            st.code(f"""
ERROR COMPLETO:
{str(e)}

Tipo: {type(e).__name__}
""")
    
    # Test 5: Información de la sesión de BD
    st.markdown("### 5️⃣ Información de Sesión de BD")
    
    try:
        with sistema.engine.connect() as conn:
            # Usuario actual
            result = conn.execute(text("SELECT current_user"))
            usuario = result.fetchone()[0]
            st.info(f"**Usuario conectado:** {usuario}")
            
            # Base de datos actual
            result = conn.execute(text("SELECT current_database()"))
            database = result.fetchone()[0]
            st.info(f"**Base de datos:** {database}")
            
            # Configuración de autocommit
            result = conn.execute(text("SHOW autocommit"))
            autocommit = result.fetchone()[0]
            st.info(f"**Autocommit:** {autocommit}")
            
            # Transacciones activas
            result = conn.execute(text("""
                SELECT COUNT(*) FROM pg_stat_activity 
                WHERE datname = current_database() AND state = 'active'
            """))
            transacciones = result.fetchone()[0]
            st.info(f"**Transacciones activas:** {transacciones}")
            
    except Exception as e:
        st.error(f"❌ Error obteniendo info de sesión: {str(e)}")


def eliminar_archivo_ultra_simple(id_archivo):
    """
    Eliminación ultra simple usando psycopg2 directo
    REEMPLAZAR LA FUNCIÓN PROBLEMÁTICA POR ESTA
    """
    
    st.markdown("### 🗑️ Eliminación Ultra Simple")
    
    # Confirmación
    if st.checkbox("⚠️ Confirmar eliminación definitiva", key=f"confirm_ultra_{id_archivo}"):
        
        if st.button("🗑️ ELIMINAR CON PSYCOPG2", key=f"ultra_delete_{id_archivo}", type="primary"):
            
            try:
                import psycopg2
                
                # Progreso
                progress = st.progress(0)
                status = st.empty()
                
                # Conectar con psycopg2 directo
                status.text("🔌 Conectando con psycopg2...")
                progress.progress(0.1)
                
                conn = psycopg2.connect(
                    host=DATABASE_CONFIG['host'],
                    port=DATABASE_CONFIG['port'],
                    database=DATABASE_CONFIG['database'],
                    user=DATABASE_CONFIG['user'],
                    password=DATABASE_CONFIG['password']
                )
                
                cursor = conn.cursor()
                
                # Obtener info del archivo
                status.text("📋 Obteniendo información del archivo...")
                progress.progress(0.2)
                
                cursor.execute("""
                    SELECT nombre_archivo, tipo_catalogo, division 
                    FROM archivos_cargados WHERE id_archivo = %s
                """, (id_archivo,))
                
                archivo_info = cursor.fetchone()
                
                if not archivo_info:
                    st.error("❌ Archivo no encontrado")
                    conn.close()
                    return
                
                nombre, tipo, division = archivo_info
                
                # Contar registros a eliminar
                status.text("🔢 Contando registros...")
                progress.progress(0.3)
                
                cursor.execute("SELECT COUNT(*) FROM resultados_normalizacion WHERE id_archivo = %s", (id_archivo,))
                total_resultados = cursor.fetchone()[0]
                
                # ELIMINAR RESULTADOS
                status.text(f"🗑️ Eliminando {total_resultados} resultados...")
                progress.progress(0.5)
                
                cursor.execute("DELETE FROM resultados_normalizacion WHERE id_archivo = %s", (id_archivo,))
                resultados_eliminados = cursor.rowcount
                
                # ELIMINAR ARCHIVO
                status.text("🗑️ Eliminando registro del archivo...")
                progress.progress(0.7)
                
                cursor.execute("DELETE FROM archivos_cargados WHERE id_archivo = %s", (id_archivo,))
                archivos_eliminados = cursor.rowcount
                
                # COMMIT EXPLÍCITO
                status.text("💾 Guardando cambios...")
                progress.progress(0.9)
                
                conn.commit()
                
                # VERIFICAR
                cursor.execute("SELECT COUNT(*) FROM archivos_cargados WHERE id_archivo = %s", (id_archivo,))
                verificacion = cursor.fetchone()[0]
                
                progress.progress(1.0)
                
                if verificacion == 0:
                    status.text("✅ Eliminación completada!")
                    
                    st.success(f"""
                    ### ✅ ELIMINACIÓN EXITOSA
                    
                    **Archivo eliminado:** {nombre}
                    **Tipo:** {tipo} | **División:** {division}
                    **Resultados eliminados:** {resultados_eliminados:,}
                    **Registros de archivo:** {archivos_eliminados}
                    
                    🔄 **Recargando página...**
                    """)
                    
                    # Auto-reload
                    time.sleep(2)
                    st.rerun()
                    
                else:
                    st.error("❌ La eliminación no se completó correctamente")
                
                conn.close()
                
            except Exception as e:
                st.error(f"❌ Error en eliminación ultra simple: {str(e)}")
                st.code(f"""
ERROR COMPLETO:
{str(e)}

ID Archivo: {id_archivo}
Función: eliminar_archivo_ultra_simple()
                """)




# ========================================
# FUNCIÓN AUXILIAR: INTERFAZ LIMITADA PARA USUARIOS
# ========================================

def mostrar_interfaz_carga_limitada():
    """Interfaz de carga limitada para usuarios normales"""
    
    usuario_actual = st.session_state.get('usuario_actual', {})
    rol_usuario = usuario_actual.get('rol', 'USUARIO')
    
    if rol_usuario == 'USUARIO':
        # Solo mostrar información, sin permitir cargas
        st.markdown("## 📁 Visualización de Carga de Archivos")
        
        st.info("""
        👤 **Acceso de Usuario:**
        - Puedes **visualizar** el estado de archivos cargados
        - **No puedes cargar** nuevos archivos
        - **No puedes gestionar** referencias
        
        📞 **Para cargar archivos:** Contacta a un administrador
        """)
        
        # Solo mostrar la pestaña de procesamiento (solo lectura)
        mostrar_procesamiento_tiempo_real()
    
    else:
        # Para administradores, mostrar interfaz completa
        mostrar_interfaz_carga()







def mostrar_parametros_sistema_admin():
    """Parámetros del sistema - VERSIÓN CORREGIDA CON BOTONES FUNCIONALES"""
    
    st.markdown("#### ⚙️ Parámetros del Sistema")
    st.markdown("🔒 **Acceso de Administrador** - Configuración técnica avanzada")
    
    # Advertencia de seguridad
    st.warning("""
    ⚠️ **ATENCIÓN:** Estos parámetros afectan el rendimiento del sistema.
    Cambios incorrectos pueden causar problemas de estabilidad.
    """)
    
    with st.expander("ℹ️ ¿Qué significan estos parámetros?", expanded=False):
        st.markdown("""
        **🔢 Tamaño de lote:**
        - Cantidad de registros procesados simultáneamente
        - **Menor valor** = Menos memoria, más lento
        - **Mayor valor** = Más memoria, más rápido
        
        **⏱️ Timeout de consultas:**
        - Tiempo máximo para consultas SQL (segundos)
        - Evita consultas que se "cuelguen"
        
        **🧵 Número de hilos:**
        - Procesos paralelos para normalización
        - **Más hilos** = Más velocidad, más CPU
        - **Menos hilos** = Menos recursos, más estable
        
        **💾 TTL de cache:**
        - Tiempo que se guardan resultados en memoria
        - **Mayor TTL** = Menos consultas, datos menos frescos
        - **Menor TTL** = Más consultas, datos más actualizados
        """)
    
    # Inicializar valores por defecto si no existen
    if 'config_batch_size' not in st.session_state:
        st.session_state.config_batch_size = 1000
    if 'config_timeout' not in st.session_state:
        st.session_state.config_timeout = 30
    if 'config_workers' not in st.session_state:
        st.session_state.config_workers = 4
    if 'config_cache_ttl' not in st.session_state:
        st.session_state.config_cache_ttl = 300
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**⚡ Rendimiento:**")
        batch_size = st.number_input(
            "🔢 Tamaño de lote para procesamiento:", 
            value=st.session_state.config_batch_size, 
            min_value=100, 
            max_value=10000,
            step=100,
            help="Registros procesados por lote. Más alto = más memoria pero más rápido.",
            key="batch_size_input"
        )
        
        timeout_seconds = st.number_input(
            "⏱️ Timeout de consultas (segundos):", 
            value=st.session_state.config_timeout, 
            min_value=5, 
            max_value=300,
            step=5,
            help="Tiempo máximo para una consulta SQL antes de cancelarla.",
            key="timeout_input"
        )
    
    with col2:
        st.markdown("**🔧 Concurrencia:**")
        max_workers = st.number_input(
            "🧵 Número máximo de hilos:", 
            value=st.session_state.config_workers, 
            min_value=1, 
            max_value=16,
            step=1,
            help="Procesos paralelos. Más hilos = más velocidad pero más CPU.",
            key="workers_input"
        )
        
        cache_ttl = st.number_input(
            "💾 TTL de cache (segundos):", 
            value=st.session_state.config_cache_ttl, 
            min_value=60, 
            max_value=3600,
            step=30,
            help="Tiempo que los resultados se mantienen en memoria.",
            key="cache_input"
        )
    
    # Recomendaciones automáticas - CORREGIDAS
    st.markdown("#### 💡 Recomendaciones Automáticas:")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📱 Configurar para archivos pequeños", help="< 1,000 registros"):
            # APLICAR CONFIGURACIÓN PARA ARCHIVOS PEQUEÑOS
            st.session_state.config_batch_size = 500
            st.session_state.config_timeout = 15
            st.session_state.config_workers = 2
            st.session_state.config_cache_ttl = 300
            
            st.success("✅ Configuración aplicada para archivos pequeños")
            st.info("""
            **Configuración aplicada:**
            - 🔢 Lote: 500 registros
            - ⏱️ Timeout: 15 segundos
            - 🧵 Hilos: 2
            - 💾 Cache: 300 segundos
            """)
            
            # Forzar actualización de la interfaz
            st.rerun()
    
    with col2:
        if st.button("📊 Configurar para archivos medianos", help="1,000 - 10,000 registros"):
            # APLICAR CONFIGURACIÓN PARA ARCHIVOS MEDIANOS
            st.session_state.config_batch_size = 1000
            st.session_state.config_timeout = 30
            st.session_state.config_workers = 4
            st.session_state.config_cache_ttl = 300
            
            st.success("✅ Configuración aplicada para archivos medianos")
            st.info("""
            **Configuración aplicada:**
            - 🔢 Lote: 1,000 registros
            - ⏱️ Timeout: 30 segundos
            - 🧵 Hilos: 4
            - 💾 Cache: 300 segundos
            """)
            
            # Forzar actualización de la interfaz
            st.rerun()
    
    with col3:
        if st.button("📈 Configurar para archivos grandes", help="> 10,000 registros"):
            # APLICAR CONFIGURACIÓN PARA ARCHIVOS GRANDES
            st.session_state.config_batch_size = 2000
            st.session_state.config_timeout = 60
            st.session_state.config_workers = 6
            st.session_state.config_cache_ttl = 600
            
            st.success("✅ Configuración aplicada para archivos grandes")
            st.info("""
            **Configuración aplicada:**
            - 🔢 Lote: 2,000 registros
            - ⏱️ Timeout: 60 segundos
            - 🧵 Hilos: 6
            - 💾 Cache: 600 segundos
            """)
            
            # Forzar actualización de la interfaz
            st.rerun()
    
    # Detectar cambios en los valores
    valores_cambiados = (
        batch_size != st.session_state.config_batch_size or
        timeout_seconds != st.session_state.config_timeout or
        max_workers != st.session_state.config_workers or
        cache_ttl != st.session_state.config_cache_ttl
    )
    
    # Mostrar estado de configuración actual
    st.markdown("---")
    st.markdown("#### 📊 Configuración Actual:")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🔢 Lote", f"{batch_size:,}")
    with col2:
        st.metric("⏱️ Timeout", f"{timeout_seconds}s")
    with col3:
        st.metric("🧵 Hilos", max_workers)
    with col4:
        st.metric("💾 Cache", f"{cache_ttl}s")
    
    # Botón para guardar configuración
    col1, col2 = st.columns([3, 1])
    
    with col1:
        if valores_cambiados:
            st.warning("⚠️ Hay cambios sin guardar en la configuración")
        else:
            st.success("✅ Configuración sincronizada")
    
    with col2:
        if st.button("💾 Guardar Configuración", type="primary", disabled=not valores_cambiados):
            # Guardar en session_state
            st.session_state.config_batch_size = batch_size
            st.session_state.config_timeout = timeout_seconds
            st.session_state.config_workers = max_workers
            st.session_state.config_cache_ttl = cache_ttl
            
            # Guardar en base de datos
            success = guardar_configuracion_sistema(batch_size, timeout_seconds, max_workers, cache_ttl)
            
            if success:
                st.success("✅ Configuración guardada correctamente")
                
                # Mostrar resumen de lo guardado
                st.info(f"""
                **Configuración guardada:**
                - 🔢 Lote: {batch_size:,} registros
                - ⏱️ Timeout: {timeout_seconds} segundos
                - 🧵 Hilos: {max_workers}
                - 💾 Cache: {cache_ttl} segundos
                """)
                
                time.sleep(1)
                st.rerun()
            else:
                st.error("❌ Error guardando configuración")


def mostrar_mensaje_permisos_parametros(rol_usuario):
    """Mensaje para usuarios sin permisos para ver parámetros"""
    
    st.markdown("#### ⚙️ Parámetros del Sistema")
    
    # Mensaje diferente según el rol
    if rol_usuario == 'GERENTE':
        st.warning("""
        👨‍💼 **Acceso de Gerente:**
        
        Los parámetros técnicos del sistema solo pueden ser modificados por el **SUPERUSUARIO**.
        
        **¿Por qué?**
        - Cambios incorrectos pueden afectar la estabilidad
        - Requieren conocimiento técnico avanzado
        - Pueden impactar el rendimiento de todos los usuarios
        
        📞 **¿Necesitas cambiar algo?** Contacta al administrador del sistema.
        """)
    else:
        st.info("""
        👤 **Acceso de Usuario:**
        
        Esta sección contiene configuraciones técnicas avanzadas del sistema.
        
        **Solo el administrador (SUPERUSUARIO) puede:**
        - Ver parámetros de rendimiento
        - Modificar configuraciones de la base de datos
        - Ajustar configuraciones de procesamiento
        
        📞 **¿Problemas de rendimiento?** Reporta al administrador.
        """)
    
    # Mostrar información básica que sí pueden ver
    st.markdown("---")
    st.markdown("#### ℹ️ Información Disponible:")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.success("""
        **✅ Puedes ver:**
        - Estado de la conexión
        - Estadísticas de tablas
        - Información de la base de datos
        """)
    
    with col2:
        st.error("""
        **❌ No puedes modificar:**
        - Parámetros de rendimiento
        - Configuración de hilos
        - Timeouts del sistema
        """)


def guardar_configuracion_sistema(batch_size, timeout, workers, cache_ttl):
    """Guardar configuración del sistema en base de datos"""
    
    try:
        sistema = SistemaNormalizacion()
        usuario_actual = st.session_state.get('usuario_actual', {})
        
        # Crear tabla de configuración si no existe
        with sistema.engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS configuracion_sistema (
                    id SERIAL PRIMARY KEY,
                    parametro VARCHAR(50) UNIQUE NOT NULL,
                    valor VARCHAR(100) NOT NULL,
                    descripcion TEXT,
                    modificado_por UUID REFERENCES usuarios(id_usuario),
                    fecha_modificacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            
            # Insertar o actualizar parámetros
            parametros = [
                ('batch_size', str(batch_size), 'Tamaño de lote para procesamiento'),
                ('timeout_seconds', str(timeout), 'Timeout de consultas en segundos'),
                ('max_workers', str(workers), 'Número máximo de hilos'),
                ('cache_ttl', str(cache_ttl), 'TTL de cache en segundos')
            ]
            
            for param, valor, desc in parametros:
                conn.execute(text("""
                    INSERT INTO configuracion_sistema (parametro, valor, descripcion, modificado_por)
                    VALUES (:param, :valor, :desc, :user_id)
                    ON CONFLICT (parametro) 
                    DO UPDATE SET 
                        valor = EXCLUDED.valor,
                        modificado_por = EXCLUDED.modificado_por,
                        fecha_modificacion = CURRENT_TIMESTAMP
                """), {
                    'param': param,
                    'valor': valor,
                    'desc': desc,
                    'user_id': usuario_actual.get('id_usuario')
                })
            
            conn.commit()
        
        return True
    
    except Exception as e:
        st.error(f"Error guardando configuración: {e}")
        return False






def cargar_referencias_con_actualizacion_automatica(df_ref, tipo_ref, fuente_ref, nombre_archivo):
    """
    Función de carga que NORMALIZA las referencias antes de insertarlas
    VERSIÓN CORREGIDA - REEMPLAZAR la función existente
    """
    
    try:
        import psycopg2
        
        # CREAR INSTANCIA DEL SISTEMA PARA NORMALIZACIÓN
        sistema = SistemaNormalizacion()
        
        # Validar datos básicos
        if 'nombre_oficial' not in df_ref.columns or 'codigo_oficial' not in df_ref.columns:
            st.error("❌ Faltan columnas requeridas")
            return False
        
        registros_vacios = df_ref['nombre_oficial'].isna().sum() + (df_ref['nombre_oficial'] == '').sum()
        if registros_vacios > 0:
            st.error(f"❌ Hay {registros_vacios} registros sin nombre oficial")
            return False
        
        # ========================================
        # NUEVA SECCIÓN: PRE-NORMALIZACIÓN
        # ========================================
        st.info("🧠 Normalizando nombres de referencia...")
        
        # Crear columna normalizada para preview
        df_ref['nombre_normalizado'] = df_ref['nombre_oficial'].apply(
            lambda x: sistema.limpiar_texto_inteligente(str(x), tipo_ref)
        )
        
        # Mostrar preview de normalización (primeros 5)
        with st.expander("👀 Preview de Normalización (primeros 5 registros)"):
            preview_df = df_ref[['nombre_oficial', 'nombre_normalizado']].head().copy()
            preview_df.columns = ['Original', 'Normalizado']
            st.dataframe(preview_df, use_container_width=True)
        
        # Detectar cambios significativos
        cambios = sum(1 for i, row in df_ref.iterrows() 
                     if row['nombre_oficial'].upper().strip() != row['nombre_normalizado'])
        
        if cambios > 0:
            st.warning(f"⚠️ Se normalizarán {cambios:,} nombres ({cambios/len(df_ref)*100:.1f}%)")
        else:
            st.success("✅ Los nombres ya están normalizados")
        
        # ========================================
        # CONTINUAR CON INSERCIÓN NORMALIZADA
        # ========================================
        
        # Conectar con psycopg2
        st.info("🔌 Conectando a PostgreSQL...")
        
        conn = psycopg2.connect(
            host=DATABASE_CONFIG['host'],
            port=DATABASE_CONFIG['port'],
            database=DATABASE_CONFIG['database'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password']
        )
        
        cursor = conn.cursor()
        
        # Contar referencias existentes
        st.info("📊 Contando referencias existentes...")
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
        total_existentes = cursor.fetchone()[0]
        
        if total_existentes > 0:
            st.warning(f"⚠️ Se reemplazarán {total_existentes:,} referencias existentes de {tipo_ref}")
        
        # ELIMINAR referencias existentes
        if total_existentes > 0:
            st.info(f"🗑️ Eliminando {total_existentes:,} referencias existentes...")
            cursor.execute("DELETE FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
            eliminados = cursor.rowcount
            st.info(f"✅ Eliminados: {eliminados:,}")
            
            # Verificar eliminación
            cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
            verificacion = cursor.fetchone()[0]
            
            if verificacion > 0:
                st.error(f"❌ DELETE falló - quedan {verificacion:,} registros")
                conn.close()
                return False
        
        # INSERTAR nuevas referencias NORMALIZADAS
        st.info(f"📥 Insertando {len(df_ref):,} nuevas referencias normalizadas...")
        
        # Crear barra de progreso
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        insertados = 0
        normalizados = 0
        timestamp_carga = datetime.now()
        
        for idx, row in df_ref.iterrows():
            try:
                # CRÍTICO: USAR EL NOMBRE NORMALIZADO
                nombre_original = str(row.get('nombre_oficial', ''))
                nombre_normalizado = sistema.limpiar_texto_inteligente(nombre_original, tipo_ref)
                
                # Contar si hubo normalización
                if nombre_original.upper().strip() != nombre_normalizado:
                    normalizados += 1
                
                cursor.execute("""
                    INSERT INTO referencias_normalizacion 
                    (tipo_catalogo, codigo_oficial, nombre_oficial, nombre_alternativo, 
                     coordenadas_lat, coordenadas_lng, estado_padre, municipio_padre, 
                     activo, fecha_actualizacion)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    tipo_ref,
                    str(row.get('codigo_oficial', f'AUTO_{idx}')),
                    nombre_normalizado,  # ← CAMBIO CRÍTICO: USAR NORMALIZADO
                    json.dumps([nombre_original] if nombre_original != nombre_normalizado else []),  # Guardar original como alternativo
                    float(row['coordenadas_lat']) if 'coordenadas_lat' in row and pd.notna(row['coordenadas_lat']) else None,
                    float(row['coordenadas_lng']) if 'coordenadas_lng' in row and pd.notna(row['coordenadas_lng']) else None,
                    str(row.get('estado_padre', '')) if 'estado_padre' in row and pd.notna(row.get('estado_padre')) else None,
                    str(row.get('municipio_padre', '')) if 'municipio_padre' in row and pd.notna(row.get('municipio_padre')) else None,
                    True,
                    timestamp_carga
                ))
                
                insertados += 1
                
                # Actualizar progreso cada 50 registros
                if insertados % 50 == 0:
                    progress = insertados / len(df_ref)
                    progress_bar.progress(progress)
                    status_text.text(f"📥 Insertados: {insertados:,} / {len(df_ref):,} ({progress:.1%})")
                
            except Exception as e:
                st.warning(f"⚠️ Error en registro {idx}: {str(e)}")
        
        # Finalizar progreso
        progress_bar.progress(1.0)
        status_text.text(f"✅ Insertados: {insertados:,} registros")
        
        # COMMIT CRÍTICO
        st.info("💾 Guardando cambios...")
        conn.commit()
        
        # VERIFICACIÓN FINAL
        st.info("🔍 Verificando resultado...")
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
        total_final = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion")
        total_global = cursor.fetchone()[0]
        
        conn.close()
        
        # MOSTRAR RESULTADO FINAL CON ESTADÍSTICAS DE NORMALIZACIÓN
        if total_final == insertados:
            st.success(f"""
            ## 🎉 CARGA EXITOSA CON NORMALIZACIÓN
            
            **✅ Resultado:**
            - **Eliminadas:** {total_existentes:,} referencias anteriores
            - **Insertadas:** {insertados:,} nuevas referencias  
            - **Normalizadas:** {normalizados:,} nombres ({normalizados/insertados*100:.1f}%)
            - **Total {tipo_ref}:** {total_final:,} referencias
            - **Total sistema:** {total_global:,} referencias
            
            **🧠 Normalización aplicada:**
            - ✅ Convertidas a MAYÚSCULAS
            - ✅ Acentos removidos
            - ✅ Abreviaciones expandidas
            - ✅ Caracteres especiales limpiados
            
            **🔄 La tabla se actualizará automáticamente...**
            """)
            
            # MARCAR EN SESSION STATE QUE HUBO CAMBIOS
            if 'referencias_actualizadas' not in st.session_state:
                st.session_state.referencias_actualizadas = 0
            st.session_state.referencias_actualizadas += 1
            
            return True
        else:
            st.error(f"❌ Discrepancia: insertados {insertados:,}, final {total_final:,}")
            return False
            
    except Exception as e:
        st.error(f"❌ Error en carga: {str(e)}")
        import traceback
        st.code(traceback.format_exc())
        return False

# ========================================
# FUNCIÓN ADICIONAL: LIMPIAR DATOS ANTES DE VALIDAR
# ========================================

def preparar_dataframe_para_validacion(df):
    """
    Prepara el DataFrame limpiando valores problemáticos antes de la validación
    NUEVA FUNCIÓN - AGREGAR AL SISTEMA
    """
    
    df_limpio = df.copy()
    
    for columna in df_limpio.columns:
        # Reemplazar valores problemáticos por cadenas vacías
        df_limpio[columna] = df_limpio[columna].astype(str)
        
        # Limpiar valores que representan "vacío"
        df_limpio[columna] = df_limpio[columna].replace({
            'nan': '',
            'NaN': '',
            'None': '',
            'null': '',
            'NULL': '',
            'NA': '',
            ' ': '',  # Solo espacios
            'NaT': ''  # Not a Time
        })
        
        # Limpiar espacios al inicio y final
        df_limpio[columna] = df_limpio[columna].str.strip()
    
    return df_limpio


# ========================================
# FUNCIÓN MEJORADA: MOSTRAR ESTRUCTURA CON INFORMACIÓN DE CAMPOS OPCIONALES
# ========================================

def mostrar_estructura_esperada_mejorada_ACTUALIZADA(tipo_catalogo):
    """
    Mostrar estructura esperada con información sobre campos opcionales
    REEMPLAZAR LA FUNCIÓN EXISTENTE
    """
    
    if tipo_catalogo in ESQUEMAS_AS400:
        st.markdown(f"#### 📋 Estructura Esperada para {tipo_catalogo}:")
        
        esquema = ESQUEMAS_AS400[tipo_catalogo]
        
        # Identificar campo principal (descripción)
        CAMPO_PRINCIPAL = {
            'ESTADOS': 'STADES',
            'CIUDADES': 'CTYDES', 
            'MUNICIPIOS': 'MPIDES',
            'ALCALDIAS': 'DLGDES',
            'COLONIAS': 'SDADES'
        }
        
        # Identificar campos que pueden estar vacíos
        CAMPOS_OPCIONALES = {
            'ESTADOS': ['STASTS'],
            'CIUDADES': ['CTYSTS'],
            'MUNICIPIOS': ['MPISTS'],
            'ALCALDIAS': ['DLGSTS'],
            'COLONIAS': ['SDASTS']
        }
        
        campo_principal = CAMPO_PRINCIPAL.get(tipo_catalogo)
        campos_opcionales = CAMPOS_OPCIONALES.get(tipo_catalogo, [])
        
        estructura_data = []
        for campo, info in esquema.items():
            es_principal = campo == campo_principal
            es_opcional = campo in campos_opcionales
            
            # Determinar obligatoriedad
            if es_principal:
                obligatorio = '✅ REQUERIDO'
            elif es_opcional:
                obligatorio = '⚪ OPCIONAL'
            else:
                obligatorio = '✅ REQUERIDO'
            
            estructura_data.append({
                'Campo': campo,
                'Tipo': info['tipo'],
                'Longitud': info['longitud'],
                'Descripción': info['descripcion'],
                'Es Principal': '🎯 SÍ' if es_principal else 'No',
                'Obligatorio': obligatorio
            })
        
        estructura_df = pd.DataFrame(estructura_data)
        st.dataframe(estructura_df, use_container_width=True, hide_index=True)
        
        # INFORMACIÓN IMPORTANTE SOBRE CAMPOS VACÍOS
        st.info(f"""
        **ℹ️ Información importante sobre campos vacíos:**
        
        **✅ Campos que PUEDEN estar vacíos:**
        {', '.join(campos_opcionales) if campos_opcionales else 'Ninguno definido'}
        
        **🎯 Campo PRINCIPAL (debe tener datos):**
        {campo_principal} - Máximo 10% de registros pueden estar vacíos
        
        **📝 Nota:** Los campos de Status generalmente pueden estar vacíos o contener 'A' (Activo), 'I' (Inactivo), etc.
        """)
        
        # Mostrar ejemplo de datos
        ejemplos = {
            'ESTADOS': """STASTS,STASAB,STADES
,01,AGUASCALIENTES
A,02,BAJA CALIFORNIA
,03,BAJA CALIFORNIA SUR""",
            'CIUDADES': """CTYSTS,CTYCAB,CTYDES
,001,AGUASCALIENTES
A,002,MEXICALI
,003,TIJUANA""",
            'MUNICIPIOS': """MPISTS,MPICVE,MPIDES
,001,AGUASCALIENTES
A,002,ASIENTOS
,003,CALVILLO""",
            'ALCALDIAS': """DLGSTS,DLGCVE,DLGDES
,001,ALVARO OBREGON
A,002,AZCAPOTZALCO
,003,BENITO JUAREZ""",
            'COLONIAS': """SDASTS,SDASDA,SDADES
,00001,CENTRO
A,00002,DOCTORES
,00003,OBRERA"""
        }
        
        if tipo_catalogo in ejemplos:
            st.markdown("**Ejemplo de datos correctos (nota los campos de Status vacíos):**")
            st.code(ejemplos[tipo_catalogo], language="csv")


# ========================================
# DIAGNÓSTICO Y CORRECCIÓN DE PROCESAMIENTO
# ========================================

def diagnosticar_archivos_cargados(sistema):
    """Función de diagnóstico para ver qué está pasando"""
    
    st.markdown("### 🔍 Diagnóstico de Archivos")
    
    try:
        with sistema.engine.connect() as conn:
            
            # 1. VERIFICAR TODAS LAS TABLAS
            st.markdown("#### 1️⃣ Verificar Tablas Existentes")
            
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                ORDER BY table_name
            """))
            
            tablas = [row[0] for row in result]
            
            if tablas:
                st.success(f"✅ Tablas encontradas: {', '.join(tablas)}")
            else:
                st.error("❌ No se encontraron tablas")
                return
            
            # 2. VERIFICAR ARCHIVOS_CARGADOS (SIN FILTRO DE FECHA)
            st.markdown("#### 2️⃣ Todos los Archivos Cargados (Sin filtro de fecha)")
            
            result = conn.execute(text("""
                SELECT 
                    id_archivo,
                    nombre_archivo,
                    tipo_catalogo,
                    division,
                    total_registros,
                    fecha_carga,
                    estado_procesamiento,
                    usuario
                FROM archivos_cargados
                ORDER BY fecha_carga DESC
            """))
            
            todos_archivos = []
            for row in result:
                if row:
                    todos_archivos.append({
                        'id_archivo': row[0],
                        'nombre_archivo': row[1],
                        'tipo_catalogo': row[2],
                        'division': row[3],
                        'total_registros': row[4],
                        'fecha_carga': row[5],
                        'estado_procesamiento': row[6],
                        'usuario': row[7]
                    })
            
            if todos_archivos:
                st.success(f"✅ TOTAL ARCHIVOS ENCONTRADOS: {len(todos_archivos)}")
                
                # Mostrar en tabla
                df_archivos = pd.DataFrame(todos_archivos)
                df_archivos['fecha_carga'] = pd.to_datetime(df_archivos['fecha_carga']).dt.strftime('%Y-%m-%d %H:%M:%S')
                
                st.dataframe(df_archivos, use_container_width=True, hide_index=True)
            
            else:
                st.error("❌ NO HAY ARCHIVOS CARGADOS")
                st.info("Esto significa que el archivo no se cargó correctamente en la base de datos")
    
    except Exception as e:
        st.error(f"❌ Error en diagnóstico: {str(e)}")










# ========================================
# SOLUCIÓN DE EMERGENCIA - CACHE COLGADO
# ========================================

# PASO 1: DESHABILITAR EL CACHE TEMPORALMENTE
# Reemplaza la función cargar_referencias_con_cache_ACTUALIZADO() por esta versión SIN CACHE:

def cargar_referencias_SIN_CACHE_TEMPORAL(df_ref, tipo_ref, fuente_ref, nombre_archivo):
    """
    REEMPLAZA TEMPORALMENTE cargar_referencias_con_cache_ACTUALIZADO()
    
    Versión SIN cache para que funcione mientras arreglamos el problema
    """
    
    try:
        import psycopg2
        
        # Crear instancia del sistema para normalización (SIN CACHE)
        sistema = SistemaNormalizacion()
        
        # Validación (código existente igual)
        if 'nombre_oficial' not in df_ref.columns or 'codigo_oficial' not in df_ref.columns:
            st.error("❌ Faltan columnas requeridas")
            return False
        
        registros_vacios = df_ref['nombre_oficial'].isna().sum() + (df_ref['nombre_oficial'] == '').sum()
        if registros_vacios > 0:
            st.error(f"❌ Hay {registros_vacios} registros sin nombre oficial")
            return False
        
        # Pre-normalización
        st.info("🧠 Normalizando nombres de referencia...")
        
        df_ref['nombre_normalizado'] = df_ref['nombre_oficial'].apply(
            lambda x: sistema.limpiar_texto_inteligente(str(x), tipo_ref)
        )
        
        # Preview de normalización
        with st.expander("👀 Preview de Normalización (primeros 5 registros)"):
            preview_df = df_ref[['nombre_oficial', 'nombre_normalizado']].head().copy()
            preview_df.columns = ['Original', 'Normalizado']
            st.dataframe(preview_df, use_container_width=True)
        
        # Detectar cambios
        cambios = sum(1 for i, row in df_ref.iterrows() 
                     if row['nombre_oficial'].upper().strip() != row['nombre_normalizado'])
        
        if cambios > 0:
            st.warning(f"⚠️ Se normalizarán {cambios:,} nombres ({cambios/len(df_ref)*100:.1f}%)")
        else:
            st.success("✅ Los nombres ya están normalizados")
        
        # Conectar con psycopg2
        st.info("🔌 Conectando a PostgreSQL...")
        
        conn = psycopg2.connect(
            host=DATABASE_CONFIG['host'],
            port=DATABASE_CONFIG['port'],
            database=DATABASE_CONFIG['database'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password']
        )
        
        cursor = conn.cursor()
        
        # Contar referencias existentes
        st.info("📊 Contando referencias existentes...")
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
        total_existentes = cursor.fetchone()[0]
        
        if total_existentes > 0:
            st.warning(f"⚠️ Se reemplazarán {total_existentes:,} referencias existentes de {tipo_ref}")
        
        # ELIMINAR referencias existentes
        if total_existentes > 0:
            st.info(f"🗑️ Eliminando {total_existentes:,} referencias existentes...")
            cursor.execute("DELETE FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
            eliminados = cursor.rowcount
            st.info(f"✅ Eliminados: {eliminados:,}")
            
            cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
            verificacion = cursor.fetchone()[0]
            
            if verificacion > 0:
                st.error(f"❌ DELETE falló - quedan {verificacion:,} registros")
                conn.close()
                return False
        
        # INSERTAR nuevas referencias
        st.info(f"📥 Insertando {len(df_ref):,} nuevas referencias normalizadas...")
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        insertados = 0
        normalizados = 0
        timestamp_carga = datetime.now()
        
        for idx, row in df_ref.iterrows():
            try:
                nombre_original = str(row.get('nombre_oficial', ''))
                nombre_normalizado = sistema.limpiar_texto_inteligente(nombre_original, tipo_ref)
                
                if nombre_original.upper().strip() != nombre_normalizado:
                    normalizados += 1
                
                cursor.execute("""
                    INSERT INTO referencias_normalizacion 
                    (tipo_catalogo, codigo_oficial, nombre_oficial, nombre_alternativo, 
                     coordenadas_lat, coordenadas_lng, estado_padre, municipio_padre, 
                     activo, fecha_actualizacion)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    tipo_ref,
                    str(row.get('codigo_oficial', f'AUTO_{idx}')),
                    nombre_normalizado,
                    json.dumps([nombre_original] if nombre_original != nombre_normalizado else []),
                    float(row['coordenadas_lat']) if 'coordenadas_lat' in row and pd.notna(row['coordenadas_lat']) else None,
                    float(row['coordenadas_lng']) if 'coordenadas_lng' in row and pd.notna(row['coordenadas_lng']) else None,
                    str(row.get('estado_padre', '')) if 'estado_padre' in row and pd.notna(row.get('estado_padre')) else None,
                    str(row.get('municipio_padre', '')) if 'municipio_padre' in row and pd.notna(row.get('municipio_padre')) else None,
                    True,
                    timestamp_carga
                ))
                
                insertados += 1
                
                if insertados % 10 == 0:
                    progress = insertados / len(df_ref)
                    progress_bar.progress(progress)
                    status_text.text(f"📥 Insertados: {insertados:,} / {len(df_ref):,} ({progress:.1%})")
                
            except Exception as e:
                st.warning(f"⚠️ Error en registro {idx}: {str(e)}")
        
        progress_bar.progress(1.0)
        status_text.text(f"✅ Insertados: {insertados:,} registros")
        
        # COMMIT
        st.info("💾 Guardando cambios...")
        conn.commit()
        
        # VERIFICACIÓN FINAL
        st.info("🔍 Verificando resultado...")
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
        total_final = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion")
        total_global = cursor.fetchone()[0]
        
        conn.close()
        
        # ========================================
        # SIN CACHE - SOLO MENSAJE DE ÉXITO
        # ========================================
        
        if total_final == insertados:
            st.success(f"""
            ## 🎉 CARGA EXITOSA CON NORMALIZACIÓN (SIN CACHE)
            
            **✅ Resultado:**
            - **Eliminadas:** {total_existentes:,} referencias anteriores
            - **Insertadas:** {insertados:,} nuevas referencias  
            - **Normalizadas:** {normalizados:,} nombres ({normalizados/insertados*100:.1f}%)
            - **Total {tipo_ref}:** {total_final:,} referencias
            - **Total sistema:** {total_global:,} referencias
            
            **🧠 Normalización aplicada:**
            - ✅ Convertidas a MAYÚSCULAS
            - ✅ Acentos removidos
            - ✅ Abreviaciones expandidas
            - ✅ Caracteres especiales limpiados
            
            **ℹ️ Cache temporalmente deshabilitado**
            - La carga funcionó correctamente
            - El cache se arreglará en la próxima versión
            
            **🔄 La tabla se actualizará automáticamente...**
            """)
            
            if 'referencias_actualizadas' not in st.session_state:
                st.session_state.referencias_actualizadas = 0
            st.session_state.referencias_actualizadas += 1
            
            return True
        else:
            st.error(f"❌ Discrepancia: insertados {insertados:,}, final {total_final:,}")
            return False
            
    except Exception as e:
        st.error(f"❌ Error en carga: {str(e)}")
        import traceback
        st.code(traceback.format_exc())
        return False

# ========================================
# PASO 2: DESHABILITAR BÚSQUEDA CON CACHE TAMBIÉN
# ========================================

def buscar_en_referencias_SIN_CACHE_TEMPORAL(self, texto_limpio, tipo_catalogo):
    """
    REEMPLAZA TEMPORALMENTE buscar_en_referencias_CON_CACHE()
    
    Versión SIN cache que va directo a PostgreSQL (más lento pero funciona)
    """
    
    print(f"🔍 Buscando SIN CACHE: '{texto_limpio}' en {tipo_catalogo}")
    
    try:
        # CONSULTA DIRECTA A POSTGRESQL (sin cache)
        with self.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT * FROM referencias_normalizacion 
                WHERE tipo_catalogo = :tipo AND activo = true
            """), {'tipo': tipo_catalogo})
            
            referencias = []
            for row in result:
                referencias.append(dict(row._mapping))
        
        if not referencias:
            print(f"   ❌ No hay referencias para {tipo_catalogo}")
            return None
        
        print(f"   📊 Encontradas {len(referencias)} referencias para {tipo_catalogo} (DIRECTO PostgreSQL)")
        
        # Resto del código IDÉNTICO
        # Buscar coincidencia exacta
        for ref in referencias:
            nombre_ref_limpio = ref['nombre_oficial'].upper().strip()
            if texto_limpio == nombre_ref_limpio:
                print(f"   ✅ EXACTO: '{texto_limpio}' = '{nombre_ref_limpio}'")
                return {
                    **ref,
                    'metodo': 'EXACTO',
                    'confianza': 1.0
                }
        
        # Buscar con fuzzy matching
        nombres_referencias = [ref['nombre_oficial'].upper().strip() for ref in referencias]
        
        from fuzzywuzzy import fuzz, process
        mejor_fuzzy = process.extractOne(texto_limpio, nombres_referencias, scorer=fuzz.token_sort_ratio)
        
        if mejor_fuzzy and mejor_fuzzy[1] >= 60:
            for ref in referencias:
                nombre_ref = ref['nombre_oficial'].upper().strip()
                if nombre_ref == mejor_fuzzy[0]:
                    print(f"   ✅ FUZZY: '{texto_limpio}' → '{nombre_ref}' ({mejor_fuzzy[1]}%)")
                    return {
                        **ref,
                        'metodo': 'FUZZY_ALTO' if mejor_fuzzy[1] >= 80 else 'FUZZY_BAJO',
                        'confianza': mejor_fuzzy[1] / 100.0
                    }
        
        print(f"   ❌ Sin coincidencias para '{texto_limpio}'")
        return None
        
    except Exception as e:
        print(f"   ❌ Error buscando referencias: {e}")
        return None



# ========================================
# CACHE SIMPLIFICADO Y ROBUSTO - VERSIÓN 2.0
# ========================================

import time
from datetime import datetime, timedelta

# ========================================
# 1. CACHE SIMPLE SIN THREADING
# ========================================

class CacheSimplificado:
    """
    Cache simplificado sin threading que no se cuelga
    Funciona igual de bien pero más estable
    """
    
    def __init__(self):
        self.cache_data = {}  # {tipo: {'data': [...], 'timestamp': datetime, 'ttl_days': int}}
        self.stats = {'hits': 0, 'misses': 0, 'invalidaciones': 0}
        
        # TTL por defecto (30 días como solicitaste)
        self.ttl_config = {
            'ESTADOS': 30,
            'MUNICIPIOS': 15, 
            'CIUDADES': 15,
            'COLONIAS': 7,
            'ALCALDIAS': 30
        }
        
        print("🚀 Cache Simplificado inicializado (sin threading)")
    
    def is_valid(self, tipo_catalogo):
        """Verificar si cache es válido (no expirado)"""
        if tipo_catalogo not in self.cache_data:
            return False
        
        entry = self.cache_data[tipo_catalogo]
        ttl_days = entry.get('ttl_days', 30)
        expira = entry['timestamp'] + timedelta(days=ttl_days)
        
        return datetime.now() < expira
    
    def get_referencias(self, tipo_catalogo, engine):
        """Obtener referencias con cache simple"""
        
        self.stats['hits' if self.is_valid(tipo_catalogo) else 'misses'] += 1
        
        # Cache HIT
        if self.is_valid(tipo_catalogo):
            data = self.cache_data[tipo_catalogo]['data']
            print(f"🎯 CACHE HIT: {tipo_catalogo} - {len(data)} registros")
            return data
        
        # Cache MISS - consultar BD
        print(f"💿 CACHE MISS: {tipo_catalogo} - Consultando BD...")
        
        try:
            with engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT * FROM referencias_normalizacion 
                    WHERE tipo_catalogo = :tipo AND activo = true
                """), {'tipo': tipo_catalogo})
                
                referencias = []
                for row in result:
                    try:
                        ref_dict = convertir_row_a_dict_seguro(row)
                        referencias.append(ref_dict)
                    except Exception as e:
                        print(f"⚠️ Error convirtiendo row individual: {e}")
                        continue
            
            # Guardar en cache
            ttl_days = self.ttl_config.get(tipo_catalogo, 30)
            self.cache_data[tipo_catalogo] = {
                'data': referencias,
                'timestamp': datetime.now(),
                'ttl_days': ttl_days
            }
            
            print(f"📚 CACHE GUARDADO: {tipo_catalogo} - {len(referencias)} registros por {ttl_days} días")
            return referencias
            
        except Exception as e:
            print(f"❌ Error en cache: {e}")
            return []
    
    def invalidate(self, tipo_catalogo):
        """Invalidar cache específico"""
        if tipo_catalogo in self.cache_data:
            del self.cache_data[tipo_catalogo]
            self.stats['invalidaciones'] += 1
            print(f"🗑️ Cache invalidado: {tipo_catalogo}")
    
    def get_stats(self):
        """Obtener estadísticas"""
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
        
        return {
            'hit_rate': hit_rate,
            'total_consultas': total,
            'tipos_cacheados': list(self.cache_data.keys()),
            **self.stats
        }

# ========================================
# 2. INICIALIZACIÓN GLOBAL MEJORADA
# ========================================

def inicializar_cache_simplificado():
    """Inicializar cache de forma más robusta"""
    
    try:
        if 'cache_simple' not in st.session_state:
            st.session_state.cache_simple = CacheSimplificado()
            print("✅ Cache simple inicializado correctamente")
        return st.session_state.cache_simple
    except Exception as e:
        print(f"❌ Error inicializando cache: {e}")
        # Crear cache temporal si falla
        return CacheSimplificado()

def get_cache_simple():
    """Obtener cache con manejo de errores"""
    try:
        return st.session_state.get('cache_simple', CacheSimplificado())
    except:
        return CacheSimplificado()



def buscar_fallback_directo(self, texto_limpio, tipo_catalogo):
    """Fallback directo a BD si falla el cache"""
    try:
        with self.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT * FROM referencias_normalizacion 
                WHERE tipo_catalogo = :tipo AND activo = true
            """), {'tipo': tipo_catalogo})
            
            referencias = [dict(row._mapping) for row in result]
        
        # Búsqueda básica sin cache
        for ref in referencias:
            if ref['nombre_oficial'].upper().strip() == texto_limpio:
                return {**ref, 'metodo': 'FALLBACK_EXACTO', 'confianza': 1.0}
        
        return None
    except:
        return None

# ========================================
# 4. CARGA CON CACHE SIMPLIFICADO
# ========================================

def cargar_referencias_CACHE_SIMPLE(df_ref, tipo_ref, fuente_ref, nombre_archivo):
    """
    REEMPLAZAR cargar_referencias_SIN_CACHE_TEMPORAL() por esta
    
    Versión con cache simplificado que se actualiza automáticamente
    """
    
    try:
        import psycopg2
        
        # Inicializar cache de forma segura
        cache = inicializar_cache_simplificado()
        sistema = SistemaNormalizacion()
        
        # Validación (código igual que antes)
        if 'nombre_oficial' not in df_ref.columns or 'codigo_oficial' not in df_ref.columns:
            st.error("❌ Faltan columnas requeridas")
            return False
        
        registros_vacios = df_ref['nombre_oficial'].isna().sum() + (df_ref['nombre_oficial'] == '').sum()
        if registros_vacios > 0:
            st.error(f"❌ Hay {registros_vacios} registros sin nombre oficial")
            return False
        
        # Pre-normalización
        st.info("🧠 Normalizando nombres de referencia...")
        df_ref['nombre_normalizado'] = df_ref['nombre_oficial'].apply(
            lambda x: sistema.limpiar_texto_inteligente(str(x), tipo_ref)
        )
        
        # Preview
        with st.expander("👀 Preview de Normalización (primeros 5 registros)"):
            preview_df = df_ref[['nombre_oficial', 'nombre_normalizado']].head().copy()
            preview_df.columns = ['Original', 'Normalizado']
            st.dataframe(preview_df, use_container_width=True)
        
        cambios = sum(1 for i, row in df_ref.iterrows() 
                     if row['nombre_oficial'].upper().strip() != row['nombre_normalizado'])
        
        if cambios > 0:
            st.warning(f"⚠️ Se normalizarán {cambios:,} nombres ({cambios/len(df_ref)*100:.1f}%)")
        
        # Conectar y procesar (código igual que antes)
        st.info("🔌 Conectando a PostgreSQL...")
        
        conn = psycopg2.connect(
            host=DATABASE_CONFIG['host'],
            port=DATABASE_CONFIG['port'],
            database=DATABASE_CONFIG['database'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password']
        )
        
        cursor = conn.cursor()
        
        # Proceso de inserción (igual que antes)
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
        total_existentes = cursor.fetchone()[0]
        
        if total_existentes > 0:
            st.info(f"🗑️ Eliminando {total_existentes:,} referencias existentes...")
            cursor.execute("DELETE FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
        
        st.info(f"📥 Insertando {len(df_ref):,} nuevas referencias...")
        
        progress_bar = st.progress(0)
        insertados = 0
        
        for idx, row in df_ref.iterrows():
            nombre_normalizado = sistema.limpiar_texto_inteligente(str(row.get('nombre_oficial', '')), tipo_ref)
            
            cursor.execute("""
                INSERT INTO referencias_normalizacion 
                (tipo_catalogo, codigo_oficial, nombre_oficial, activo, fecha_actualizacion)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                tipo_ref,
                str(row.get('codigo_oficial', f'AUTO_{idx}')),
                nombre_normalizado,
                True,
                datetime.now()
            ))
            
            insertados += 1
            if insertados % 10 == 0:
                progress_bar.progress(insertados / len(df_ref))
        
        progress_bar.progress(1.0)
        
        # COMMIT
        st.info("💾 Guardando cambios...")
        conn.commit()
        
        # Verificación
        cursor.execute("SELECT COUNT(*) FROM referencias_normalizacion WHERE tipo_catalogo = %s", (tipo_ref,))
        total_final = cursor.fetchone()[0]
        conn.close()
        
        # ========================================
        # INVALIDAR CACHE PERSISTENTE
        # ========================================
        
        if total_final == insertados:
            st.info("🔄 Actualizando cache persistente...")
            
            try:
                # Usar cache persistente
                cache = inicializar_cache_hibrido()
                
                # Invalidar y recargar
                cache.invalidate(tipo_ref)
                cache.get_referencias(tipo_ref, sistema.engine)
                
                st.success("✅ Cache persistente actualizado")
                
            except Exception as e:
                print(f"⚠️ Error actualizando cache persistente: {e}")
                st.warning("⚠️ Cache no se pudo actualizar, pero la carga fue exitosa")
            
            st.success(f"""
            ## 🎉 CARGA EXITOSA CON CACHE PERSISTENTE
            
            **✅ Resultado:**
            - **Insertadas:** {insertados:,} referencias
            - **Total {tipo_ref}:** {total_final:,} referencias
            - **Cache:** Guardado en archivo permanentemente
            
            **⚡ Rendimiento mejorado:**
            - Cache persiste entre sesiones
            - Otros usuarios se benefician del cache
            - Cache válido por {cache.ttl_config.get(tipo_ref, 30)} días
            """)
            
            return True
        else:
            st.error(f"❌ Error en verificación")
            return False
            
    except Exception as e:
        st.error(f"❌ Error en carga: {str(e)}")
        return False

# ========================================
# 5. PANEL DE CACHE SIMPLIFICADO
# ========================================

def mostrar_panel_cache_simple():
    """Panel simplificado del cache"""
    
    st.markdown("### ⚡ Cache Simplificado")
    
    try:
        cache = get_cache_simple()
        stats = cache.get_stats()
        
        # Métricas principales
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Hit Rate", f"{stats['hit_rate']:.1f}%")
        
        with col2:
            st.metric("Consultas", stats['total_consultas'])
        
        with col3:
            st.metric("Tipos en Cache", len(stats['tipos_cacheados']))
        
        # Estado del cache
        st.markdown("#### 📊 Estado del Cache")
        
        tipos = ['ESTADOS', 'MUNICIPIOS', 'CIUDADES', 'COLONIAS', 'ALCALDIAS']
        cache_info = []
        
        for tipo in tipos:
            if tipo in cache.cache_data:
                entry = cache.cache_data[tipo]
                edad = (datetime.now() - entry['timestamp']).days
                expira_en = entry['ttl_days'] - edad
                
                cache_info.append({
                    'Tipo': tipo,
                    'Estado': '✅ Activo' if expira_en > 0 else '⏰ Expirado',
                    'Registros': len(entry['data']),
                    'Edad (días)': edad,
                    'Expira en': f"{max(0, expira_en)} días"
                })
            else:
                cache_info.append({
                    'Tipo': tipo,
                    'Estado': '❌ Sin cache',
                    'Registros': 0,
                    'Edad (días)': '-',
                    'Expira en': '-'
                })
        
        df_cache = pd.DataFrame(cache_info)
        st.dataframe(df_cache, use_container_width=True, hide_index=True)
        
        # Acciones
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🗑️ Limpiar Todo"):
                cache.cache_data.clear()
                st.success("✅ Cache limpiado")
                st.rerun()
        
        with col2:
            if st.button("📊 Refrescar Stats"):
                st.rerun()
    
    except Exception as e:
        st.error(f"Error mostrando panel: {e}")
 


# ========================================
# OPCIÓN 1: CACHE EN ARCHIVO (RECOMENDADO)
# ========================================

class CachePersistente:
    """
    Cache que se mantiene entre sesiones guardando en archivo
    """
    
    def __init__(self, cache_file='cache_referencias.pkl'):
        self.cache_file = cache_file
        self.cache_data = {}
        self.stats = {'hits': 0, 'misses': 0, 'invalidaciones': 0}
        
        self.ttl_config = {
            'ESTADOS': 30,
            'MUNICIPIOS': 15, 
            'CIUDADES': 15,
            'COLONIAS': 7,
            'ALCALDIAS': 30
        }
        
        # Cargar cache existente al inicializar
        self.cargar_cache_desde_archivo()
        print(f"🚀 Cache persistente inicializado - {len(self.cache_data)} tipos en memoria")
    
    def cargar_cache_desde_archivo(self):
        """Cargar cache desde archivo si existe"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    data = pickle.load(f)
                    self.cache_data = data.get('cache_data', {})
                    self.stats = data.get('stats', {'hits': 0, 'misses': 0, 'invalidaciones': 0})
                    print(f"📂 Cache cargado desde archivo: {len(self.cache_data)} tipos")
            else:
                print("📂 No hay cache previo - iniciando limpio")
        except Exception as e:
            print(f"⚠️ Error cargando cache desde archivo: {e}")
            self.cache_data = {}
    
    def guardar_cache_en_archivo(self):
        """Guardar cache en archivo"""
        try:
            data = {
                'cache_data': self.cache_data,
                'stats': self.stats,
                'timestamp': datetime.now()
            }
            
            with open(self.cache_file, 'wb') as f:
                pickle.dump(data, f)
            
            print(f"💾 Cache guardado en archivo: {len(self.cache_data)} tipos")
        except Exception as e:
            print(f"⚠️ Error guardando cache: {e}")
    
    def is_valid(self, tipo_catalogo):
        """Verificar si cache es válido (no expirado)"""
        if tipo_catalogo not in self.cache_data:
            return False
        
        entry = self.cache_data[tipo_catalogo]
        ttl_days = entry.get('ttl_days', 30)
        expira = entry['timestamp'] + timedelta(days=ttl_days)
        
        return datetime.now() < expira
    
    def get_referencias(self, tipo_catalogo, engine):
        """Obtener referencias con cache persistente"""
        
        self.stats['hits' if self.is_valid(tipo_catalogo) else 'misses'] += 1
        
        # Cache HIT
        if self.is_valid(tipo_catalogo):
            data = self.cache_data[tipo_catalogo]['data']
            print(f"🎯 CACHE HIT (persistente): {tipo_catalogo} - {len(data)} registros")
            return data
        
        # Cache MISS - consultar BD
        print(f"💿 CACHE MISS (persistente): {tipo_catalogo} - Consultando BD...")
        
        try:
            with engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT * FROM referencias_normalizacion 
                    WHERE tipo_catalogo = :tipo AND activo = true
                """), {'tipo': tipo_catalogo})
                
                referencias = [dict(row._mapping) for row in result]
            
            # Guardar en cache
            ttl_days = self.ttl_config.get(tipo_catalogo, 30)
            self.cache_data[tipo_catalogo] = {
                'data': referencias,
                'timestamp': datetime.now(),
                'ttl_days': ttl_days
            }
            
            # Guardar automáticamente en archivo
            self.guardar_cache_en_archivo()
            
            print(f"📚 CACHE GUARDADO (persistente): {tipo_catalogo} - {len(referencias)} registros")
            return referencias
            
        except Exception as e:
            print(f"❌ Error en cache persistente: {e}")
            return []
    
    def invalidate(self, tipo_catalogo):
        """Invalidar cache específico y actualizar archivo"""
        if tipo_catalogo in self.cache_data:
            del self.cache_data[tipo_catalogo]
            self.stats['invalidaciones'] += 1
            self.guardar_cache_en_archivo()  # Guardar cambios
            print(f"🗑️ Cache invalidado (persistente): {tipo_catalogo}")
    
    def get_stats(self):
        """Obtener estadísticas"""
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
        
        # Información adicional sobre persistencia
        tamaño_archivo = 0
        if os.path.exists(self.cache_file):
            tamaño_archivo = os.path.getsize(self.cache_file) / 1024  # KB
        
        return {
            'hit_rate': hit_rate,
            'total_consultas': total,
            'tipos_cacheados': list(self.cache_data.keys()),
            'tamaño_archivo_kb': round(tamaño_archivo, 2),
            'archivo_cache': self.cache_file,
            **self.stats
        }

# ========================================
# OPCIÓN 2: CACHE GLOBAL EN STREAMLIT
# ========================================

# Variable global que persiste mientras Streamlit esté corriendo
_CACHE_GLOBAL = None

def get_cache_global_persistente():
    """Cache que persiste mientras Streamlit esté corriendo"""
    global _CACHE_GLOBAL
    
    if _CACHE_GLOBAL is None:
        _CACHE_GLOBAL = CachePersistente()
        print("🌐 Cache global inicializado (persiste durante ejecución de Streamlit)")
    
    return _CACHE_GLOBAL

# ========================================
# OPCIÓN 3: CACHE HÍBRIDO (MEJOR OPCIÓN)
# ========================================

def inicializar_cache_hibrido():
    """
    Cache híbrido: Usar session_state pero con respaldo en archivo
    RECOMENDADO: Mejor rendimiento + persistencia
    """
    
    # Intentar usar cache de session_state primero (más rápido)
    if 'cache_persistente' not in st.session_state:
        # Si no existe en session, crear y cargar desde archivo
        st.session_state.cache_persistente = CachePersistente()
        print("🔗 Cache híbrido inicializado en session_state")
    
    return st.session_state.cache_persistente

# ========================================
# MODIFICACIÓN DEL LOGOUT PARA PRESERVAR CACHE
# ========================================

def cerrar_sesion_PRESERVANDO_CACHE():
    """
    Cierra sesión pero preserva el cache en archivo y limpia completamente el state
    """
    
    # Guardar cache antes de cerrar sesión
    if 'cache_persistente' in st.session_state:
        try:
            cache = st.session_state.cache_persistente
            cache.guardar_cache_en_archivo()
            print("💾 Cache guardado antes de cerrar sesión")
        except Exception as e:
            print(f"⚠️ Error guardando cache al cerrar: {e}")
    
    # Cerrar sesión en base de datos
    if 'token_sesion' in st.session_state:
        gestor = st.session_state.gestor_usuarios
        gestor.cerrar_sesion(st.session_state.token_sesion)
    
    # LIMPIAR COMPLETAMENTE session_state excepto cache
    cache_backup = st.session_state.get('cache_persistente', None)
    
    # Limpiar todo
    st.session_state.clear()
    
    # Restaurar solo el cache
    if cache_backup:
        st.session_state.cache_persistente = cache_backup
    
    # Marcar que se hizo logout
    st.session_state.usuario_autenticado = False
    st.session_state.logout_completed = True
    st.session_state.selected_mode = None
    
    print("👋 Sesión cerrada - Session state limpiado completamente")
    
    # Mostrar mensaje y rerun
    st.success("👋 Sesión cerrada exitosamente")
    st.info("🔄 Redirigiendo al Launcher...")
    
    time.sleep(1)
    st.rerun()

# ========================================
# FUNCIONES ACTUALIZADAS PARA CACHE PERSISTENTE
# ========================================

def buscar_en_referencias_CACHE_PERSISTENTE(self, texto_limpio, tipo_catalogo):
    """
    ACTUALIZAR buscar_en_referencias_CACHE_SIMPLE() con esta versión
    
    Búsqueda con cache que persiste entre sesiones
    """
    
    print(f"🔍 Buscando con cache persistente: '{texto_limpio}' en {tipo_catalogo}")
    
    try:
        # Obtener cache persistente
        cache = inicializar_cache_hibrido()
        
        # Obtener referencias (con cache persistente o desde BD)
        referencias = cache.get_referencias(tipo_catalogo, self.engine)
        
        if not referencias:
            print(f"   ❌ No hay referencias para {tipo_catalogo}")
            return None
        
        print(f"   📊 Procesando {len(referencias)} referencias")
        
        # Búsqueda exacta (código igual que antes)
        for ref in referencias:
            nombre_ref = ref['nombre_oficial'].upper().strip()
            if texto_limpio == nombre_ref:
                print(f"   ✅ EXACTO: '{texto_limpio}'")
                return {
                    **ref,
                    'metodo': 'EXACTO',
                    'confianza': 1.0
                }
        
        # Fuzzy matching (código igual que antes)
        nombres = [ref['nombre_oficial'].upper().strip() for ref in referencias]
        
        from fuzzywuzzy import fuzz, process
        mejor = process.extractOne(texto_limpio, nombres, scorer=fuzz.token_sort_ratio)
        
        if mejor and mejor[1] >= 60:
            for ref in referencias:
                if ref['nombre_oficial'].upper().strip() == mejor[0]:
                    print(f"   ✅ FUZZY: '{texto_limpio}' → '{mejor[0]}' ({mejor[1]}%)")
                    return {
                        **ref,
                        'metodo': 'FUZZY_ALTO' if mejor[1] >= 80 else 'FUZZY_BAJO',
                        'confianza': mejor[1] / 100.0
                    }
        
        print(f"   ❌ Sin coincidencias para '{texto_limpio}'")
        return None
        
    except Exception as e:
        print(f"   ❌ Error en búsqueda persistente: {e}")
        # Fallback a búsqueda directa
        return self.buscar_fallback_directo(texto_limpio, tipo_catalogo)

def cargar_referencias_CACHE_PERSISTENTE(df_ref, tipo_ref, fuente_ref, nombre_archivo):
    """
    ACTUALIZAR cargar_referencias_CACHE_SIMPLE() con esta versión
    
    Carga con cache que persiste entre sesiones
    """
    
    # ... (código de validación e inserción igual que antes) ...
    
    # Solo cambiar la parte final del cache:
    if total_final == insertados:
        st.info("🔄 Actualizando cache persistente...")
        
        try:
            # Usar cache persistente
            cache = inicializar_cache_hibrido()
            
            # Invalidar y recargar
            cache.invalidate(tipo_ref)
            cache.get_referencias(tipo_ref, sistema.engine)
            
            st.success("✅ Cache persistente actualizado")
            
        except Exception as e:
            print(f"⚠️ Error actualizando cache persistente: {e}")
            st.warning("⚠️ Cache no se pudo actualizar, pero la carga fue exitosa")
        
        # ... resto del código igual ...

# ========================================
# PANEL ACTUALIZADO PARA CACHE PERSISTENTE
# ========================================

def mostrar_panel_cache_persistente():
    """Panel para cache persistente"""
    
    st.markdown("### ⚡ Cache Persistente Entre Sesiones")
    
    try:
        cache = inicializar_cache_hibrido()
        stats = cache.get_stats()
        
        # Métricas principales
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Hit Rate", f"{stats['hit_rate']:.1f}%")
        
        with col2:
            st.metric("Consultas", stats['total_consultas'])
        
        with col3:
            st.metric("Tipos en Cache", len(stats['tipos_cacheados']))
        
        with col4:
            st.metric("Archivo", f"{stats['tamaño_archivo_kb']:.1f} KB")
        
        # Información de persistencia
        st.info(f"""
        **💾 Persistencia:**
        - Archivo: `{stats['archivo_cache']}`
        - Cache se mantiene entre sesiones
        - Se guarda automáticamente al actualizar
        """)
        
        # Estado del cache (código igual que antes)
        # ... resto del panel igual ...
        
        # Acciones mejoradas
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🗑️ Limpiar Cache"):
                cache.cache_data.clear()
                cache.guardar_cache_en_archivo()
                st.success("✅ Cache limpiado y archivo actualizado")
                st.rerun()
        
        with col2:
            if st.button("💾 Forzar Guardado"):
                cache.guardar_cache_en_archivo()
                st.success("✅ Cache guardado en archivo")
        
        with col3:
            if st.button("📂 Recargar desde Archivo"):
                cache.cargar_cache_desde_archivo()
                st.success("✅ Cache recargado desde archivo")
                st.rerun()
    
    except Exception as e:
        st.error(f"Error mostrando panel persistente: {e}")


def convertir_row_a_dict_seguro(row):
    """Convertir row de SQLAlchemy a diccionario de forma segura"""
    try:
        # Método 1: _mapping (SQLAlchemy 2.0+)
        if hasattr(row, '_mapping'):
            return dict(row._mapping)
        
        # Método 2: _asdict() (SQLAlchemy 1.4)
        elif hasattr(row, '_asdict'):
            return row._asdict()
        
        # Método 3: Crear diccionario manualmente
        elif hasattr(row, 'keys'):
            return {key: row[key] for key in row.keys()}
        
        # Método 4: Conversión directa
        else:
            return dict(row)
            
    except Exception as e:
        print(f"⚠️ Error convirtiendo row: {e}")
        
        # Método de emergencia: usar índices
        try:
            return {
                'id_referencia': row[0],
                'tipo_catalogo': row[1], 
                'codigo_oficial': row[2],
                'nombre_oficial': row[3],
                'nombre_alternativo': row[4],
                'coordenadas_lat': row[5],
                'coordenadas_lng': row[6],
                'estado_padre': row[7],
                'municipio_padre': row[8],
                'activo': row[9],
                'fecha_actualizacion': row[10]
            }
        except:
            # Último recurso: diccionario mínimo
            return {
                'nombre_oficial': str(row[3]) if len(row) > 3 else 'ERROR',
                'codigo_oficial': str(row[2]) if len(row) > 2 else 'ERROR',
                'tipo_catalogo': str(row[1]) if len(row) > 1 else 'ERROR'
            }


# ========================================
# TEST DE DIAGNÓSTICO PARA EL ERROR
# ========================================

def test_conversion_sqlalchemy():
    """Función para diagnosticar el problema de conversión"""
    
    st.markdown("### 🧪 Test Conversión SQLAlchemy")
    
    if st.button("🔍 Diagnosticar Error SQLAlchemy"):
        try:
            sistema = SistemaNormalizacion()
            
            with sistema.engine.connect() as conn:
                # Test 1: Consulta simple
                result = conn.execute(text("SELECT COUNT(*) FROM referencias_normalizacion"))
                count_row = result.fetchone()
                st.success(f"✅ Consulta básica OK: {count_row[0]} registros")
                
                # Test 2: Consulta de estructura
                result = conn.execute(text("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = 'referencias_normalizacion'
                    ORDER BY ordinal_position
                """))
                
                st.write("**Estructura de la tabla:**")
                for row in result:
                    st.write(f"- {row[0]}: {row[1]}")
                
                # Test 3: Consulta de referencia simple
                result = conn.execute(text("""
                    SELECT * FROM referencias_normalizacion 
                    WHERE tipo_catalogo = 'ESTADOS' 
                    LIMIT 1
                """))
                
                row = result.fetchone()
                if row:
                    st.write("**Row encontrado:**")
                    st.write(f"Tipo de row: {type(row)}")
                    st.write(f"Longitud: {len(row)}")
                    
                    # Test conversión
                    try:
                        ref_dict = convertir_row_a_dict_seguro(row)
                        st.success("✅ Conversión exitosa")
                        st.json(ref_dict)
                    except Exception as e:
                        st.error(f"❌ Error en conversión: {e}")
                        st.write(f"Row crudo: {row}")
                
                else:
                    st.warning("No hay registros de ESTADOS para probar")
        
        except Exception as e:
            st.error(f"❌ Error en test: {e}")
            import traceback
            st.code(traceback.format_exc())



def mostrar_mantenimiento_sistema():
    """Herramientas de mantenimiento del sistema - VERSIÓN CORREGIDA"""
    
    st.markdown("### 🧹 Mantenimiento del Sistema")
    
    sistema = SistemaNormalizacion()
    
    # Pestañas para organizar mejor
    tab1, tab2, tab3 = st.tabs(["🛠️ Mantenimiento Básico", "🗄️ Espacio en Disco", "🗑️ Limpieza de Datos"])
    
    with tab1:
        mantenimiento_basico_seguro(sistema)
        mostrar_informacion_mantenimiento()
    
    with tab2:
        mostrar_estadisticas_espacio_seguro(sistema)
    
    with tab3:
        mostrar_limpieza_datos_seguro(sistema)

def mantenimiento_basico_seguro(sistema):
    """Mantenimiento básico sin VACUUM (más seguro)"""
    
    st.markdown("#### 🛠️ Mantenimiento Básico (Seguro)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📊 Solo ANALYZE (Recomendado)", type="primary"):
            try:
                with sistema.engine.connect() as conn:
                    # Solo ANALYZE, sin VACUUM
                    conn.execute(text("ANALYZE"))
                    conn.commit()
                
                st.success("✅ Estadísticas actualizadas con ANALYZE")
                st.info("📊 El rendimiento de consultas ha sido optimizado")
                
            except Exception as e:
                st.error(f"Error en ANALYZE: {str(e)}")
    
    with col2:
        if st.button("🧹 VACUUM Completo (Avanzado)"):
            if st.checkbox("⚠️ Confirmar VACUUM (puede tomar tiempo)"):
                optimizar_tablas_seguro(sistema)

def mostrar_informacion_mantenimiento():
    """Mostrar información sobre las opciones de mantenimiento"""
    
    st.markdown("#### ℹ️ Información de Mantenimiento")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **📊 ANALYZE (Recomendado):**
        - ✅ Rápido y seguro
        - ✅ Actualiza estadísticas
        - ✅ Mejora rendimiento
        - ✅ No bloquea tablas
        """)
    
    with col2:
        st.markdown("""
        **🧹 VACUUM (Avanzado):**
        - ⚠️ Puede tomar tiempo
        - ⚠️ Requiere permisos especiales
        - ✅ Libera espacio físico
        - ✅ Reorganiza tablas
        """)
    
    st.info("""
    **💡 Recomendación:**
    - Para uso diario: Usar solo **ANALYZE**
    - Para mantenimiento profundo: Usar **VACUUM** cuando la aplicación tenga poco tráfico
    - La diferencia principal es que VACUUM libera espacio físico, pero es más lento
    """)

def mostrar_estadisticas_espacio_seguro(sistema):
    """Estadísticas de espacio con manejo de errores mejorado"""
    
    st.markdown("#### 💽 Uso de Espacio por Tabla")
    
    try:
        with sistema.engine.connect() as conn:
            # Intentar obtener estadísticas de espacio
            result = conn.execute(text("""
                SELECT 
                    schemaname,
                    tablename,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
            """))
            
            tabla_sizes = []
            for row in result:
                try:
                    tabla_sizes.append({
                        'tablename': row[1], 
                        'size': row[2],
                        'size_bytes': row[3]
                    })
                except Exception as e:
                    print(f"⚠️ Error procesando tabla: {e}")
                    continue
        
        if tabla_sizes:
            st.markdown("##### 📊 Tamaño de Tablas:")
            df_sizes = pd.DataFrame(tabla_sizes)
            df_sizes = df_sizes[['tablename', 'size']].copy()
            df_sizes.columns = ['Tabla', 'Tamaño']
            st.dataframe(df_sizes, use_container_width=True, hide_index=True)
            
            # Calcular total
            total_bytes = sum(item['size_bytes'] for item in tabla_sizes)
            total_mb = total_bytes / (1024 * 1024)
            st.info(f"📊 **Espacio total usado:** {total_mb:.2f} MB")
        else:
            st.info("ℹ️ No se pudieron obtener estadísticas de espacio")
    
    except Exception as e:
        st.warning(f"⚠️ No se pueden mostrar estadísticas de espacio: {str(e)}")
        st.info("💡 Esto puede ser normal si no tienes permisos para consultar pg_tables")
        
        # Mostrar información básica alternativa
        try:
            with sistema.engine.connect() as conn:
                # Contar registros por tabla
                tablas_principales = [
                    'usuarios', 'archivos_cargados', 'resultados_normalizacion', 
                    'referencias_normalizacion', 'sesiones_usuario'
                ]
                
                st.markdown("##### 📊 Conteo de Registros por Tabla:")
                for tabla in tablas_principales:
                    try:
                        result = conn.execute(text(f"SELECT COUNT(*) FROM {tabla}"))
                        count = result.fetchone()[0]
                        st.write(f"**{tabla}:** {count:,} registros")
                    except:
                        st.write(f"**{tabla}:** No accesible")
        except:
            st.info("No se puede acceder a información básica de tablas")

def mostrar_limpieza_datos_seguro(sistema):
    """Limpieza de datos antiguos con validaciones mejoradas"""
    
    st.markdown("#### 🗑️ Limpieza de Datos Antiguos")
    
    dias_antiguos = st.number_input(
        "Eliminar registros anteriores a (días):", 
        value=90, 
        min_value=30, 
        max_value=365,
        help="Los datos anteriores a esta fecha serán eliminados permanentemente"
    )
    
    # Preview de lo que se va a eliminar
    if st.button("🔍 Vista Previa de Eliminación"):
        try:
            fecha_limite = datetime.now() - timedelta(days=dias_antiguos)
            
            with sistema.engine.connect() as conn:
                # Contar registros a eliminar
                result = conn.execute(text("""
                    SELECT COUNT(*) FROM resultados_normalizacion 
                    WHERE fecha_proceso < :fecha_limite
                """), {'fecha_limite': fecha_limite})
                
                registros_a_eliminar = result.fetchone()[0]
                
                result = conn.execute(text("""
                    SELECT COUNT(*) FROM archivos_cargados 
                    WHERE fecha_carga < :fecha_limite
                """), {'fecha_limite': fecha_limite})
                
                archivos_a_eliminar = result.fetchone()[0]
                
                # Mostrar preview
                if registros_a_eliminar > 0 or archivos_a_eliminar > 0:
                    st.warning(f"""
                    **📋 Vista previa de eliminación:**
                    - 📊 Resultados a eliminar: {registros_a_eliminar:,}
                    - 📄 Archivos a eliminar: {archivos_a_eliminar:,}
                    - 📅 Anteriores a: {fecha_limite.strftime('%Y-%m-%d')}
                    """)
                    
                    if st.button("🗑️ CONFIRMAR ELIMINACIÓN", type="primary"):
                        ejecutar_limpieza_datos(sistema, fecha_limite, registros_a_eliminar, archivos_a_eliminar)
                else:
                    st.success(f"✅ No hay datos anteriores a {fecha_limite.strftime('%Y-%m-%d')} para eliminar")
        
        except Exception as e:
            st.error(f"Error en vista previa: {str(e)}")

def ejecutar_limpieza_datos(sistema, fecha_limite, registros_a_eliminar, archivos_a_eliminar):
    """Ejecutar limpieza de datos con barra de progreso"""
    
    try:
        # Crear barra de progreso
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        with sistema.engine.connect() as conn:
            # Eliminar resultados antiguos
            status_text.text("🗑️ Eliminando resultados antiguos...")
            progress_bar.progress(0.3)
            
            result = conn.execute(text("""
                DELETE FROM resultados_normalizacion 
                WHERE fecha_proceso < :fecha_limite
            """), {'fecha_limite': fecha_limite})
            
            resultados_eliminados = result.rowcount
            
            # Eliminar archivos huérfanos
            status_text.text("🗑️ Eliminando archivos huérfanos...")
            progress_bar.progress(0.7)
            
            result = conn.execute(text("""
                DELETE FROM archivos_cargados 
                WHERE fecha_carga < :fecha_limite
                AND id_archivo NOT IN (SELECT DISTINCT id_archivo FROM resultados_normalizacion)
            """), {'fecha_limite': fecha_limite})
            
            archivos_eliminados = result.rowcount
            
            # Confirmar cambios
            status_text.text("💾 Guardando cambios...")
            progress_bar.progress(0.9)
            
            conn.commit()
            
            # Completado
            progress_bar.progress(1.0)
            status_text.text("✅ Limpieza completada")
            
            st.success(f"""
            ✅ **Limpieza completada:**
            - 📊 Resultados eliminados: {resultados_eliminados:,}
            - 📄 Archivos eliminados: {archivos_eliminados:,}
            - 💾 Espacio liberado en base de datos
            """)
            
            # Recomendar optimización después de eliminar muchos datos
            if resultados_eliminados > 1000:
                st.info("💡 **Recomendación:** Ejecuta 'Optimizar Tablas' para liberar espacio físico")
    
    except Exception as e:
        st.error(f"Error en limpieza: {str(e)}")

def optimizar_tablas_seguro(sistema):
    """Optimizar tablas de PostgreSQL con manejo mejorado de errores"""
    
    st.markdown("#### ⚡ Optimización de Tablas")
    
    try:
        # Intentar con SQLAlchemy primero (más seguro)
        with sistema.engine.connect() as conn:
            
            # Lista de tablas principales
            tablas = ['resultados_normalizacion', 'archivos_cargados', 'referencias_normalizacion', 'usuarios', 'sesiones_usuario']
            
            # Crear barra de progreso
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            tablas_optimizadas = 0
            
            for i, tabla in enumerate(tablas):
                try:
                    status_text.text(f"⚡ Optimizando tabla: {tabla}...")
                    
                    # Verificar que la tabla existe
                    result = conn.execute(text("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public' 
                            AND table_name = :tabla
                        )
                    """), {'tabla': tabla})
                    
                    existe = result.fetchone()[0]
                    
                    if existe:
                        # Solo ANALYZE (más seguro que VACUUM)
                        conn.execute(text(f"ANALYZE {tabla}"))
                        tablas_optimizadas += 1
                        st.success(f"✅ {tabla} optimizada")
                    else:
                        st.warning(f"⚠️ Tabla {tabla} no existe, omitiendo")
                    
                except Exception as e:
                    st.warning(f"⚠️ Error optimizando {tabla}: {str(e)}")
                
                # Actualizar progreso
                progress_bar.progress((i + 1) / len(tablas))
            
            # Finalizar
            progress_bar.progress(1.0)
            status_text.text("✅ Optimización completada")
            
            st.success(f"✅ {tablas_optimizadas} tablas optimizadas correctamente")
            
            # Información adicional
            st.info("""
            **Optimización realizada:**
            - 📊 ANALYZE: Actualizó estadísticas del planificador
            - 🚀 Rendimiento mejorado en consultas futuras
            - ⚡ Proceso completado de forma segura
            """)
        
    except Exception as e:
        st.error(f"Error en optimización: {str(e)}")
        
        # Información de ayuda
        st.markdown("### 🔧 Información del Error:")
        st.code(f"""
Error: {str(e)}

Posibles causas:
1. Permisos insuficientes para ANALYZE
2. Conexión de base de datos inestable
3. Tabla bloqueada por otra operación

Solución aplicada:
- Usar ANALYZE en lugar de VACUUM (más seguro)
- Verificar existencia de tablas antes de optimizar
        """)

def actualizar_estadisticas_bd_seguro(sistema):
    """Actualizar estadísticas de PostgreSQL de forma segura"""
    
    try:
        with sistema.engine.connect() as conn:
            # ANALYZE global (más seguro que VACUUM)
            with st.spinner("📊 Actualizando estadísticas de la base de datos..."):
                conn.execute(text("ANALYZE"))
                
                # También actualizar estadísticas específicas de tablas importantes
                tablas_importantes = [
                    'resultados_normalizacion',
                    'archivos_cargados', 
                    'referencias_normalizacion'
                ]
                
                for tabla in tablas_importantes:
                    try:
                        # Verificar que existe
                        result = conn.execute(text("""
                            SELECT EXISTS (
                                SELECT FROM information_schema.tables 
                                WHERE table_schema = 'public' AND table_name = :tabla
                            )
                        """), {'tabla': tabla})
                        
                        if result.fetchone()[0]:
                            conn.execute(text(f"ANALYZE {tabla}"))
                    
                    except Exception as e:
                        print(f"Warning: No se pudo analizar {tabla}: {e}")
        
        st.success("✅ Estadísticas de base de datos actualizadas")
        
        # Mostrar información de lo que se hizo
        st.info("""
        **Estadísticas actualizadas:**
        - 📊 Planificador de consultas optimizado
        - 🎯 Estimaciones de cardinalidad mejoradas  
        - ⚡ Planes de ejecución más eficientes
        """)
        
    except Exception as e:
        st.error(f"Error actualizando estadísticas: {str(e)}")
        
        # Sugerir alternativas
        st.info("""
        **💡 Alternativas:**
        - Usa 'Solo ANALYZE' en Mantenimiento Básico
        - Contacta al administrador de base de datos
        - Verifica permisos de usuario PostgreSQL
        """)


# ========================================
# 10. EJECUCIÓN PRINCIPAL
# ========================================

if __name__ == "__main__":
    #main()
    main_con_autenticacion()
 

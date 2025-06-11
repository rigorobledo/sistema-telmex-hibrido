"""
Utilidades para el Sistema Asíncrono
===================================

Funciones de apoyo que usan todos los módulos.
"""

import os
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse
import psycopg2
from psycopg2.extras import RealDictCursor

try:
    from async_processor.config import AsyncConfig
except ImportError:
    from config import AsyncConfig

class AsyncUtils:
    """Funciones útiles para el sistema asíncrono"""
    
    @staticmethod
    def detect_environment():
        """Detectar si estamos en Railway o local"""
        is_railway = os.getenv('RAILWAY_ENVIRONMENT') is not None
        return {
            'is_railway': is_railway,
            'is_local': not is_railway,
            'environment_name': 'Railway' if is_railway else 'Local'
        }
    
    @staticmethod
    def generate_task_id():
        """Generar ID único para una tarea"""
        timestamp = int(time.time() * 1000)
        random_part = str(uuid.uuid4())[:8]
        return f"task_{timestamp}_{random_part}"
    
    @staticmethod
    def estimate_processing_time(num_records, tipo_catalogo):
        """Calcular tiempo estimado de procesamiento en segundos"""
        
        # Obtener factores de tiempo de la configuración
        factors = {
            'ESTADOS': 2,
            'MUNICIPIOS': 4,
            'CIUDADES': 4,
            'COLONIAS': 8,
            'ALCALDIAS': 3
        }
        
        factor = factors.get(tipo_catalogo, 5)
        
        # Calcular: (registros / 1000) * factor
        estimated = (num_records / 1000) * factor
        
        # Mínimo 5 segundos, máximo según configuración
        max_seconds = AsyncConfig.TASK_TIMEOUT_MINUTES * 60
        return max(5, min(max_seconds, int(estimated)))
    
    @staticmethod
    def format_duration(seconds):
        """Convertir segundos a formato legible: 2m 30s"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            minutes = seconds // 60
            secs = seconds % 60
            return f"{minutes}m {secs}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    @staticmethod
    def get_user_limits(user_role):
        """Obtener límites del usuario según su rol"""
        return AsyncConfig.USER_LIMITS.get(user_role, AsyncConfig.USER_LIMITS['USUARIO'])
    
    @staticmethod
    def calculate_file_hash(file_content):
        """Calcular hash de archivo para detectar duplicados"""
        if isinstance(file_content, str):
            file_content = file_content.encode('utf-8')
        return hashlib.md5(file_content).hexdigest()
    
    @staticmethod
    def get_database_config():
        """Obtener configuración de BD igual que el sistema principal"""
        
        env = AsyncUtils.detect_environment()
        
        if env['is_railway']:
            # RAILWAY - Igual que sistema principal
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
                return {
                    'host': os.environ['DB_HOST'],
                    'port': int(os.environ.get('DB_PORT', 5432)),
                    'database': os.environ['DB_NAME'],
                    'user': os.environ['DB_USER'],
                    'password': os.environ['DB_PASSWORD']
                }
        else:
            # LOCAL - Igual que sistema principal
            return {
                'host': os.getenv('LOCAL_DB_HOST', 'localhost'),
                'port': int(os.getenv('LOCAL_DB_PORT', 5432)),
                'database': os.getenv('LOCAL_DB_NAME', 'normalizacion_domicilios'),
                'user': os.getenv('LOCAL_DB_USER', 'postgres'),
                'password': os.getenv('LOCAL_DB_PASSWORD', 'admin123')
            }
    
    @staticmethod
    def get_db_connection():
        """Conectarse a PostgreSQL (reutiliza config del sistema principal)"""
        try:
            config = AsyncUtils.get_database_config()
            
            conn = psycopg2.connect(
                host=config['host'],
                port=config['port'],
                database=config['database'],
                user=config['user'],
                password=config['password'],
                cursor_factory=RealDictCursor
            )
            
            return conn
            
        except Exception as e:
            print(f"Error conectando a BD: {e}")
            return None
    
    @staticmethod
    def validate_file_for_async(df, tipo_catalogo, user_role):
        """Validar si archivo puede procesarse asíncrono"""
        
        num_records = len(df)
        limits = AsyncUtils.get_user_limits(user_role)
        
        # Verificar límites de rol
        if limits['max_records_per_file'] != -1:
            if num_records > limits['max_records_per_file']:
                return False, f"Archivo excede límite de {limits['max_records_per_file']:,} registros para rol {user_role}"
        
        # Verificar umbral mínimo
        if num_records < AsyncConfig.AUTO_ASYNC_THRESHOLD:
            return False, f"Archivo muy pequeño ({num_records:,} registros) - usar procesamiento síncrono"
        
        return True, "Archivo válido para procesamiento asíncrono"
    
    @staticmethod
    def test_connection():
        """Probar conexión a base de datos"""
        try:
            conn = AsyncUtils.get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                conn.close()
                return True, "Conexión exitosa"
            else:
                return False, "No se pudo conectar"
        except Exception as e:
            return False, f"Error: {str(e)}"

# Función de prueba
def test_utils():
    """Probar que las utilidades funcionan"""
    print("Probando utilidades...")
    
    # Probar ambiente
    env = AsyncUtils.detect_environment()
    print(f"Ambiente: {env['environment_name']}")
    
    # Probar ID de tarea
    task_id = AsyncUtils.generate_task_id()
    print(f"ID generado: {task_id}")
    
    # Probar estimación de tiempo
    tiempo = AsyncUtils.estimate_processing_time(5000, 'COLONIAS')
    tiempo_legible = AsyncUtils.format_duration(tiempo)
    print(f"Tiempo estimado para 5000 COLONIAS: {tiempo_legible}")
    
    # Probar conexión BD
    success, message = AsyncUtils.test_connection()
    print(f"Base de datos: {message}")
    
    print("Pruebas completadas")

# Si ejecutas este archivo directamente, hacer pruebas
if __name__ == "__main__":
    test_utils()
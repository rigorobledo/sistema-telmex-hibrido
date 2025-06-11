"""
Configuración del Sistema Asíncrono
==================================

Este archivo tiene TODA la configuración.
Solo cambia los números aquí para modificar el comportamiento.
"""

import os

class AsyncConfig:
    """Panel de control del sistema - EDITA ESTOS NÚMEROS"""
    
    # ¿A partir de cuántos registros usar asíncrono automáticamente?
    AUTO_ASYNC_THRESHOLD = 5000  # Cambias este número aquí
    
    # ¿Cuántos workers (trabajadores) máximo?
    MAX_WORKERS = 8
    
    # ¿Cuánto tiempo máximo por tarea? (minutos)
    TASK_TIMEOUT_MINUTES = 30
    
    # ¿Después de cuántos días limpiar tareas?
    CLEANUP_DAYS = 7
    
    # Límites por rol de usuario
    USER_LIMITS = {
        'USUARIO': {
            'max_files_in_queue': 3,
            'max_records_per_file': 50000,
            'priority': 1
        },
        'GERENTE': {
            'max_files_in_queue': 8,
            'max_records_per_file': 100000,
            'priority': 2
        },
        'SUPERUSUARIO': {
            'max_files_in_queue': -1,  # Ilimitado
            'max_records_per_file': -1,
            'priority': 3
        }
    }
    
    # ¿Usar Redis? (más rápido)
    USE_REDIS = True
    
    # ¿Usar memoria si Redis falla? (más lento pero siempre funciona)
    FALLBACK_TO_MEMORY = True
    
    @classmethod
    def is_development(cls):
        """¿Estamos en desarrollo (tu PC) o producción (Railway)?"""
        return os.getenv('RAILWAY_ENVIRONMENT') is None
    
    @classmethod
    def print_config(cls):
        """Mostrar configuración actual"""
        print("=" * 40)
        print("CONFIGURACIÓN ASÍNCRONA")
        print("=" * 40)
        print(f"Umbral asíncrono: {cls.AUTO_ASYNC_THRESHOLD:,} registros")
        print(f"Workers máximos: {cls.MAX_WORKERS}")
        print(f"Timeout: {cls.TASK_TIMEOUT_MINUTES} minutos")
        print(f"Ambiente: {'Local' if cls.is_development() else 'Railway'}")
        print("=" * 40)

# Mostrar configuración cuando se importa
if AsyncConfig.is_development():
    AsyncConfig.print_config()
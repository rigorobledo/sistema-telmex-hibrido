"""
Motor de Procesamiento Asíncrono
==============================

El "cerebro" del sistema asíncrono.
Procesa las tareas reutilizando el código del sistema principal.
"""

import time
import threading
from datetime import datetime
import pandas as pd
import sys
import os

# Importar componentes del sistema asíncrono
try:
    from async_processor.config import AsyncConfig
    from async_processor.utils import AsyncUtils
    from async_processor.queue_manager import QueueManager, TaskInfo
except ImportError:
    from config import AsyncConfig
    from utils import AsyncUtils
    from queue_manager import QueueManager, TaskInfo

class AsyncProcessor:
    """Motor principal de procesamiento asíncrono"""
    
    def __init__(self):
        self.queue_manager = QueueManager()
        self.workers = {}  # Workers activos
        self.is_running = False
        self.sistema_principal = None  # Referencia al sistema principal
        
        print(f"AsyncProcessor inicializado")
        print(f"Workers máximos: {AsyncConfig.MAX_WORKERS}")
    
    def initialize_main_system(self):
        """Inicializar el sistema principal para reutilizar su código"""
        try:
            # Importar el sistema principal
            sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            # Intentar importar el sistema principal
            from sistema_completo_normalizacion import SistemaNormalizacion
            
            self.sistema_principal = SistemaNormalizacion()
            print("✅ Sistema principal inicializado para reutilizar código")
            return True
            
        except Exception as e:
            print(f"⚠️ No se pudo importar sistema principal: {e}")
            print("ℹ️ Se usará modo de prueba")
            return False
    
    def submit_task(self, file_data, file_name, tipo_catalogo, division, user_id, user_role):
        """Enviar una nueva tarea para procesamiento asíncrono"""
        
        try:
            # Validar archivo
            num_records = len(file_data)
            is_valid, message = AsyncUtils.validate_file_for_async(file_data, tipo_catalogo, user_role)
            
            if not is_valid:
                return False, message
            
            # Verificar límites del usuario
            user_limits = AsyncUtils.get_user_limits(user_role)
            user_tasks = self.queue_manager.get_user_tasks(user_id)
            
            # Contar tareas pendientes/procesando
            pending_tasks = [t for t in user_tasks if t.status in ['PENDING', 'PROCESSING']]
            
            if user_limits['max_files_in_queue'] != -1:
                if len(pending_tasks) >= user_limits['max_files_in_queue']:
                    return False, f"Has alcanzado el límite de {user_limits['max_files_in_queue']} archivos en cola"
            
            # Crear información de la tarea
            task_info = TaskInfo(
                task_id=AsyncUtils.generate_task_id(),
                user_id=user_id,
                file_name=file_name,
                tipo_catalogo=tipo_catalogo,
                division=division,
                num_records=num_records,
                priority=user_limits['priority']
            )
            
            # Guardar datos del archivo temporalmente (en el futuro, podríamos usar Redis)
            self._save_file_data(task_info.task_id, file_data)
            
            # Encolar tarea
            success = self.queue_manager.enqueue_task(task_info)
            
            if success:
                # Iniciar workers si no están corriendo
                self._ensure_workers_running()
                
                return True, f"Tarea {task_info.task_id} encolada exitosamente. Estimado: {AsyncUtils.format_duration(task_info.estimated_duration)}"
            else:
                return False, "Error encolando la tarea"
                
        except Exception as e:
            return False, f"Error creando tarea: {str(e)}"
    
    def get_task_status(self, task_id):
        """Obtener estado de una tarea"""
        return self.queue_manager.get_task_status(task_id)
    
    def get_user_tasks(self, user_id):
        """Obtener todas las tareas de un usuario"""
        return self.queue_manager.get_user_tasks(user_id)
    
    def get_system_stats(self):
        """Obtener estadísticas del sistema"""
        queue_stats = self.queue_manager.get_queue_stats()
        
        return {
            'workers_active': len([w for w in self.workers.values() if w.get('active', False)]),
            'workers_max': AsyncConfig.MAX_WORKERS,
            'is_running': self.is_running,
            **queue_stats
        }
    
    def _ensure_workers_running(self):
        """Asegurar que hay workers corriendo"""
        if not self.is_running:
            self.start_workers()
    
    def start_workers(self):
        """Iniciar workers para procesar tareas"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Inicializar sistema principal si no está listo
        if self.sistema_principal is None:
            self.initialize_main_system()
        
        # Crear workers
        for i in range(min(AsyncConfig.MAX_WORKERS, 2)):  # Empezar con 2 workers
            worker_id = f"worker_{i+1}"
            
            worker_thread = threading.Thread(
                target=self._worker_loop,
                args=(worker_id,),
                daemon=True
            )
            
            self.workers[worker_id] = {
                'thread': worker_thread,
                'active': True,
                'current_task': None,
                'processed_count': 0
            }
            
            worker_thread.start()
            print(f"✅ Worker {worker_id} iniciado")
        
        print(f"🚀 Sistema asíncrono iniciado con {len(self.workers)} workers")
    
    def _worker_loop(self, worker_id):
        """Loop principal de un worker"""
        print(f"🔄 Worker {worker_id} iniciado")
        
        while self.is_running:
            try:
                # Obtener siguiente tarea
                task = self.queue_manager.get_next_task()
                
                if task:
                    print(f"📝 Worker {worker_id} procesando {task.task_id}")
                    
                    # Actualizar estado del worker
                    self.workers[worker_id]['current_task'] = task.task_id
                    
                    # Procesar la tarea
                    success = self._process_task(task, worker_id)
                    
                    # Actualizar estadísticas
                    self.workers[worker_id]['processed_count'] += 1
                    self.workers[worker_id]['current_task'] = None
                    
                    if success:
                        print(f"✅ Worker {worker_id} completó {task.task_id}")
                    else:
                        print(f"❌ Worker {worker_id} falló en {task.task_id}")
                
                else:
                    # No hay tareas, esperar un poco
                    time.sleep(2)
                    
            except Exception as e:
                print(f"❌ Error en worker {worker_id}: {e}")
                time.sleep(5)
        
        print(f"🛑 Worker {worker_id} detenido")
    
    def _process_task(self, task, worker_id):
        """Procesar una tarea específica"""
        try:
            start_time = time.time()
            
            # Actualizar estado a PROCESSING
            self.queue_manager.update_task_progress(task.task_id, 0, 'PROCESSING')
            
            # Cargar datos del archivo
            file_data = self._load_file_data(task.task_id)
            if file_data is None:
                raise Exception("No se pudieron cargar los datos del archivo")
            
            # Simular progreso 10%
            self.queue_manager.update_task_progress(task.task_id, 10, 'PROCESSING')
            
            if self.sistema_principal:
                # USAR EL SISTEMA PRINCIPAL REAL
                success = self._process_with_main_system(task, file_data, worker_id)
            else:
                # MODO DE PRUEBA
                success = self._process_in_test_mode(task, file_data, worker_id)
            
            # Progreso final
            duration = int(time.time() - start_time)
            
            if success:
                self.queue_manager.complete_task(task.task_id, True)
                print(f"✅ Tarea {task.task_id} completada en {AsyncUtils.format_duration(duration)}")
            else:
                self.queue_manager.complete_task(task.task_id, False, "Error en procesamiento")
            
            # Limpiar archivo temporal
            self._cleanup_file_data(task.task_id)
            
            return success
            
        except Exception as e:
            print(f"❌ Error procesando {task.task_id}: {e}")
            self.queue_manager.complete_task(task.task_id, False, str(e))
            self._cleanup_file_data(task.task_id)
            return False
    
    def _process_with_main_system(self, task, file_data, worker_id):
        """Procesar usando el sistema principal real"""
        try:
            print(f"🔧 Procesando con sistema principal: {task.task_id}")
            
            # Validar estructura (igual que sistema principal)
            valido, mensaje = self.sistema_principal.validar_estructura_archivo(file_data, task.tipo_catalogo)
            
            if not valido:
                raise Exception(f"Validación falló: {mensaje}")
            
            # Progreso 30%
            self.queue_manager.update_task_progress(task.task_id, 30, 'PROCESSING')
            
            # Procesar archivo (igual que sistema principal)
            exito, mensaje = self.sistema_principal.procesar_archivo_cargado(
                file_data, task.tipo_catalogo, task.division, task.file_name
            )
            
            # Progreso 90%
            self.queue_manager.update_task_progress(task.task_id, 90, 'PROCESSING')
            
            return exito
            
        except Exception as e:
            print(f"❌ Error en sistema principal: {e}")
            return False
    
    def _process_in_test_mode(self, task, file_data, worker_id):
        """Procesar en modo de prueba (cuando no hay sistema principal)"""
        try:
            print(f"🧪 Procesando en modo prueba: {task.task_id}")
            
            total_records = len(file_data)
            
            # Simular procesamiento con progreso
            for i in range(0, 101, 10):
                time.sleep(0.2)  # Simular trabajo
                self.queue_manager.update_task_progress(task.task_id, i, 'PROCESSING')
            
            print(f"✅ Modo prueba completado: {total_records} registros")
            return True
            
        except Exception as e:
            print(f"❌ Error en modo prueba: {e}")
            return False
    
    def _save_file_data(self, task_id, file_data):
        """Guardar datos del archivo temporalmente"""
        try:
            # Por ahora, guardar en memoria (en el futuro podríamos usar Redis)
            if not hasattr(self, '_temp_files'):
                self._temp_files = {}
            
            self._temp_files[task_id] = file_data
            
        except Exception as e:
            print(f"Error guardando datos temporales: {e}")
    
    def _load_file_data(self, task_id):
        """Cargar datos del archivo temporal"""
        try:
            if hasattr(self, '_temp_files') and task_id in self._temp_files:
                return self._temp_files[task_id]
            else:
                return None
                
        except Exception as e:
            print(f"Error cargando datos temporales: {e}")
            return None
    
    def _cleanup_file_data(self, task_id):
        """Limpiar datos temporales del archivo"""
        try:
            if hasattr(self, '_temp_files') and task_id in self._temp_files:
                del self._temp_files[task_id]
                
        except Exception as e:
            print(f"Error limpiando datos temporales: {e}")
    
    def stop_workers(self):
        """Detener todos los workers"""
        print("🛑 Deteniendo sistema asíncrono...")
        self.is_running = False
        
        # Esperar a que terminen las tareas actuales
        for worker_id, worker_info in self.workers.items():
            if worker_info['current_task']:
                print(f"⏳ Esperando que {worker_id} termine {worker_info['current_task']}")
        
        time.sleep(2)
        self.workers.clear()
        print("✅ Sistema asíncrono detenido")

# Función de prueba
def test_async_processor():
    """Probar el motor asíncrono"""
    print("🧪 PROBANDO MOTOR ASÍNCRONO...")
    
    # Crear processor
    processor = AsyncProcessor()
    
    # Crear datos de prueba
    test_data = pd.DataFrame({
        'STASTS': ['A', 'A', 'A'],
        'STASAB': ['01', '02', '03'],
        'STADES': ['AGUASCALIENTES', 'BAJA CALIFORNIA', 'BAJA CALIFORNIA SUR']
    })
    
    # Enviar tarea de prueba
    success, message = processor.submit_task(
        file_data=test_data,
        file_name="test_async.csv",
        tipo_catalogo="ESTADOS",
        division="TEST",
        user_id="test_user",
        user_role="GERENTE"
    )
    
    print(f"Tarea enviada: {success} - {message}")
    
    if success:
        # Esperar un poco y ver estadísticas
        time.sleep(3)
        
        stats = processor.get_system_stats()
        print(f"Estadísticas: {stats}")
        
        # Esperar que termine
        time.sleep(5)
        
        # Verificar tareas del usuario
        user_tasks = processor.get_user_tasks("test_user")
        if user_tasks:
            for task in user_tasks:
                print(f"Tarea {task.task_id}: {task.status} ({task.progress}%)")
    
    # Detener sistema
    processor.stop_workers()
    print("🎉 Prueba completada")

if __name__ == "__main__":
    test_async_processor()
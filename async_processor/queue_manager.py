"""
Gestor de Colas para Procesamiento Asíncrono
==========================================

Maneja las colas de tareas con fallback automático:
- Intenta usar Redis (más rápido)
- Si falla, usa memoria (más lento pero siempre funciona)
"""
import uuid
import time
import threading
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

try:
    from async_processor.config import AsyncConfig
    from async_processor.utils import AsyncUtils
except ImportError:
    from config import AsyncConfig
    from utils import AsyncUtils

@dataclass
class TaskInfo:
    """Información de una tarea en cola"""
    task_id: str
    user_id: str
    file_name: str
    tipo_catalogo: str
    division: str
    num_records: int
    status: str = 'PENDING'
    created_at: datetime = None
    progress: float = 0.0
    estimated_duration: int = 0
    priority: int = 1
    error_message: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.estimated_duration == 0:
            self.estimated_duration = AsyncUtils.estimate_processing_time(
                self.num_records, self.tipo_catalogo
            )

class QueueManager:
    """Gestor inteligente de colas"""
    
    def __init__(self):
        self.backend_type = 'memory'  # Por ahora solo memoria
        self.tasks = {}  # Cache de todas las tareas
        self.queues = {
            'high': [],    # SUPERUSUARIO
            'normal': [],  # GERENTE
            'low': []      # USUARIO
        }
        self.lock = threading.Lock()
        self.stats = {
            'total_enqueued': 0,
            'total_processed': 0,
            'total_failed': 0
        }
        
        print(f"QueueManager inicializado con backend: {self.backend_type}")
    
    def enqueue_task(self, task_info: TaskInfo) -> bool:
        """Encolar una tarea según su prioridad"""
        try:
            # Determinar cola según prioridad
            queue_name = self._get_queue_by_priority(task_info.priority)
            
            # Agregar a cache
            self.tasks[task_info.task_id] = task_info
            
            # Agregar a cola
            with self.lock:
                self.queues[queue_name].append(task_info)
            
            # Actualizar estadísticas
            self.stats['total_enqueued'] += 1
            
            # Guardar en base de datos
            self._save_task_to_db(task_info)
            
            print(f"Tarea {task_info.task_id} encolada en {queue_name}")
            print(f"Estimado: {AsyncUtils.format_duration(task_info.estimated_duration)}")
            
            return True
            
        except Exception as e:
            print(f"Error encolando tarea {task_info.task_id}: {e}")
            return False
    
    def _get_queue_by_priority(self, priority: int) -> str:
        """Determinar cola según prioridad del usuario"""
        if priority >= 3:
            return 'high'      # SUPERUSUARIO
        elif priority == 2:
            return 'normal'    # GERENTE
        else:
            return 'low'       # USUARIO
    
    def get_next_task(self) -> Optional[TaskInfo]:
        """Obtener la siguiente tarea a procesar (por prioridad)"""
        with self.lock:
            # Buscar en orden de prioridad
            for queue_name in ['high', 'normal', 'low']:
                if self.queues[queue_name]:
                    task = self.queues[queue_name].pop(0)
                    task.status = 'PROCESSING'
                    return task
        
        return None
    
    def update_task_progress(self, task_id: str, progress: float, status: str = None):
        """Actualizar progreso de una tarea"""
        if task_id in self.tasks:
            self.tasks[task_id].progress = progress
            if status:
                self.tasks[task_id].status = status
            
            # Actualizar en BD también
            self._update_task_in_db(task_id, progress, status)
    
    def complete_task(self, task_id: str, success: bool, error_message: str = None):
        """Marcar tarea como completada"""
        if task_id in self.tasks:
            self.tasks[task_id].status = 'SUCCESS' if success else 'FAILURE'
            self.tasks[task_id].progress = 100.0
            if error_message:
                self.tasks[task_id].error_message = error_message
            
            # Actualizar estadísticas
            if success:
                self.stats['total_processed'] += 1
            else:
                self.stats['total_failed'] += 1
            
            # Actualizar en BD
            self._update_task_in_db(task_id, 100.0, self.tasks[task_id].status)
    
    def get_task_status(self, task_id: str) -> Optional[TaskInfo]:
        """Obtener estado de una tarea"""
        return self.tasks.get(task_id)
    
    def get_user_tasks(self, user_id: str) -> List[TaskInfo]:
        """Obtener todas las tareas de un usuario"""
        return [task for task in self.tasks.values() if task.user_id == user_id]
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas de las colas"""
        with self.lock:
            return {
                'pending_by_priority': {
                    'high': len(self.queues['high']),
                    'normal': len(self.queues['normal']),
                    'low': len(self.queues['low'])
                },
                'total_pending': sum(len(q) for q in self.queues.values()),
                'total_tasks': len(self.tasks),
                'stats': self.stats.copy()
            }
    
    def _save_task_to_db(self, task_info: TaskInfo):
        """Guardar tarea en base de datos"""
        try:
            conn = AsyncUtils.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            
            # Insertar en archivos_cargados con campos adicionales
            cursor.execute("""
            INSERT INTO archivos_cargados 
            (id_archivo, nombre_archivo, tipo_catalogo, division, total_registros,
            usuario, estado_procesamiento, processing_mode, task_id, estimated_duration)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                str(uuid.uuid4()),  # ← NUEVO UUID para id_archivo
                task_info.file_name,
                task_info.tipo_catalogo,
                task_info.division,
                task_info.num_records,
                task_info.user_id,
                'PENDING',
                'ASINCRONO',
                task_info.task_id,  # task_id separado
                task_info.estimated_duration
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error guardando tarea en BD: {e}")
    
    def _update_task_in_db(self, task_id: str, progress: float, status: str = None):
        """Actualizar tarea en base de datos"""
        try:
            conn = AsyncUtils.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            
            if status:
                cursor.execute("""
                    UPDATE archivos_cargados 
                    SET estado_procesamiento = %s
                    WHERE task_id = %s
                """, (status, task_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error actualizando tarea en BD: {e}")

# Función de prueba
def test_queue_manager():
    """Probar el gestor de colas"""
    print("Probando QueueManager...")
    
    # Crear gestor
    queue_mgr = QueueManager()
    
    # Crear tarea de prueba
    task = TaskInfo(
        task_id=AsyncUtils.generate_task_id(),
        user_id="test_user",
        file_name="test.csv",
        tipo_catalogo="COLONIAS",
        division="TEST",
        num_records=5000,
        priority=2
    )
    
    # Encolar tarea
    success = queue_mgr.enqueue_task(task)
    print(f"Tarea encolada: {success}")
    
    # Ver estadísticas
    stats = queue_mgr.get_queue_stats()
    print(f"Estadísticas: {stats}")
    
    # Obtener siguiente tarea
    next_task = queue_mgr.get_next_task()
    if next_task:
        print(f"Siguiente tarea: {next_task.task_id}")
        
        # Simular progreso
        queue_mgr.update_task_progress(next_task.task_id, 50.0, 'PROCESSING')
        queue_mgr.complete_task(next_task.task_id, True)
        
        print(f"Estado final: {queue_mgr.get_task_status(next_task.task_id).status}")
    
    print("Pruebas completadas")

if __name__ == "__main__":
    test_queue_manager()
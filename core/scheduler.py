"""
EDR Windows Agent - Task Scheduler
"""

import time
import logging
import threading
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime, timedelta
from queue import Queue, Empty
import heapq

class ScheduledTask:
    """Represents a scheduled task"""
    
    def __init__(self, task_id: str, func: Callable, args: tuple = (), kwargs: dict = None, 
                 interval: float = None, next_run: datetime = None, max_runs: int = None):
        self.task_id = task_id
        self.func = func
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.interval = interval  # seconds
        self.next_run = next_run or datetime.utcnow()
        self.max_runs = max_runs
        self.run_count = 0
        self.last_run = None
        self.is_running = False
        self.created_at = datetime.utcnow()
    
    def __lt__(self, other):
        """For priority queue comparison"""
        return self.next_run < other.next_run
    
    def execute(self):
        """Execute the task"""
        try:
            self.is_running = True
            self.last_run = datetime.utcnow()
            self.run_count += 1
            
            result = self.func(*self.args, **self.kwargs)
            
            # Schedule next run if recurring
            if self.interval and (self.max_runs is None or self.run_count < self.max_runs):
                self.next_run = datetime.utcnow() + timedelta(seconds=self.interval)
            else:
                self.next_run = None  # Mark as completed
            
            return result
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Task {self.task_id} failed: {e}")
            return None
        finally:
            self.is_running = False
    
    def should_run(self) -> bool:
        """Check if task should run now"""
        return (self.next_run is not None and 
                datetime.utcnow() >= self.next_run and 
                not self.is_running)
    
    def is_completed(self) -> bool:
        """Check if task is completed"""
        return (self.next_run is None or 
                (self.max_runs is not None and self.run_count >= self.max_runs))

class TaskScheduler:
    """Task scheduler for EDR Agent"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.running = False
        
        # Task storage
        self.tasks: Dict[str, ScheduledTask] = {}
        self.task_queue = []  # Priority queue
        self.immediate_queue = Queue()  # For immediate execution
        
        # Threading
        self.scheduler_thread = None
        self.worker_threads = []
        self.task_lock = threading.Lock()
        self.max_workers = 4
        
        self.logger.info("✅ Task scheduler initialized")
    
    def start(self):
        """Start the task scheduler"""
        try:
            self.running = True
            
            # Start scheduler thread
            self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self.scheduler_thread.start()
            
            # Start worker threads
            for i in range(self.max_workers):
                worker = threading.Thread(target=self._worker_loop, daemon=True)
                worker.start()
                self.worker_threads.append(worker)
            
            self.logger.info("✅ Task scheduler started")
            
        except Exception as e:
            self.logger.error(f"Failed to start scheduler: {e}")
            raise
    
    def stop(self):
        """Stop the task scheduler"""
        try:
            self.running = False
            
            # Wait for threads to finish
            if self.scheduler_thread and self.scheduler_thread.is_alive():
                self.scheduler_thread.join(timeout=5)
            
            for worker in self.worker_threads:
                if worker.is_alive():
                    worker.join(timeout=2)
            
            self.logger.info("✅ Task scheduler stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping scheduler: {e}")
    
    def schedule_recurring(self, task_id: str, func: Callable, interval: float, 
                         args: tuple = (), kwargs: dict = None, max_runs: int = None) -> bool:
        """Schedule a recurring task"""
        try:
            with self.task_lock:
                if task_id in self.tasks:
                    self.logger.warning(f"Task {task_id} already exists, replacing...")
                
                task = ScheduledTask(
                    task_id=task_id,
                    func=func,
                    args=args,
                    kwargs=kwargs or {},
                    interval=interval,
                    max_runs=max_runs
                )
                
                self.tasks[task_id] = task
                heapq.heappush(self.task_queue, task)
            
            self.logger.info(f"✅ Scheduled recurring task: {task_id} (interval: {interval}s)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to schedule task {task_id}: {e}")
            return False
    
    def schedule_once(self, task_id: str, func: Callable, delay: float = 0, 
                     args: tuple = (), kwargs: dict = None) -> bool:
        """Schedule a one-time task"""
        try:
            with self.task_lock:
                next_run = datetime.utcnow() + timedelta(seconds=delay)
                
                task = ScheduledTask(
                    task_id=task_id,
                    func=func,
                    args=args,
                    kwargs=kwargs or {},
                    next_run=next_run,
                    max_runs=1
                )
                
                self.tasks[task_id] = task
                heapq.heappush(self.task_queue, task)
            
            self.logger.info(f"✅ Scheduled one-time task: {task_id} (delay: {delay}s)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to schedule task {task_id}: {e}")
            return False
    
    def run_immediately(self, func: Callable, args: tuple = (), kwargs: dict = None):
        """Run a task immediately in worker thread"""
        try:
            task_data = {
                'func': func,
                'args': args or (),
                'kwargs': kwargs or {}
            }
            
            self.immediate_queue.put(task_data)
            self.logger.debug("✅ Task queued for immediate execution")
            
        except Exception as e:
            self.logger.error(f"Failed to queue immediate task: {e}")
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a scheduled task"""
        try:
            with self.task_lock:
                if task_id in self.tasks:
                    # Mark as completed to prevent further execution
                    self.tasks[task_id].next_run = None
                    del self.tasks[task_id]
                    
                    # Rebuild heap without the cancelled task
                    self.task_queue = [task for task in self.task_queue 
                                     if task.task_id != task_id]
                    heapq.heapify(self.task_queue)
                    
                    self.logger.info(f"✅ Cancelled task: {task_id}")
                    return True
                else:
                    self.logger.warning(f"Task {task_id} not found")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to cancel task {task_id}: {e}")
            return False
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a task"""
        try:
            with self.task_lock:
                if task_id in self.tasks:
                    task = self.tasks[task_id]
                    return {
                        'task_id': task.task_id,
                        'is_running': task.is_running,
                        'run_count': task.run_count,
                        'max_runs': task.max_runs,
                        'last_run': task.last_run.isoformat() if task.last_run else None,
                        'next_run': task.next_run.isoformat() if task.next_run else None,
                        'created_at': task.created_at.isoformat(),
                        'interval': task.interval,
                        'is_completed': task.is_completed()
                    }
                else:
                    return None
                    
        except Exception as e:
            self.logger.error(f"Error getting task status: {e}")
            return None
    
    def list_tasks(self) -> List[Dict[str, Any]]:
        """List all tasks"""
        try:
            with self.task_lock:
                return [self.get_task_status(task_id) for task_id in self.tasks.keys()]
                
        except Exception as e:
            self.logger.error(f"Error listing tasks: {e}")
            return []
    
    def process_tasks(self):
        """Process pending tasks (called from main agent loop)"""
        try:
            with self.task_lock:
                # Check for tasks ready to run
                current_time = datetime.utcnow()
                ready_tasks = []
                
                while self.task_queue and self.task_queue[0].next_run <= current_time:
                    task = heapq.heappop(self.task_queue)
                    if task.should_run():
                        ready_tasks.append(task)
                
                # Execute ready tasks
                for task in ready_tasks:
                    try:
                        # Run in separate thread
                        thread = threading.Thread(
                            target=self._execute_task_safe,
                            args=(task,),
                            daemon=True
                        )
                        thread.start()
                        
                        # Reschedule if recurring
                        if not task.is_completed():
                            heapq.heappush(self.task_queue, task)
                            
                    except Exception as e:
                        self.logger.error(f"Error processing task {task.task_id}: {e}")
                
                # Clean up completed tasks
                self._cleanup_completed_tasks()
                
        except Exception as e:
            self.logger.error(f"Error in process_tasks: {e}")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                self.process_tasks()
                time.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Error in scheduler loop: {e}")
                time.sleep(5)
    
    def _worker_loop(self):
        """Worker thread loop for immediate tasks"""
        while self.running:
            try:
                # Get immediate task
                try:
                    task_data = self.immediate_queue.get(timeout=1)
                except Empty:
                    continue
                
                # Execute task
                try:
                    func = task_data['func']
                    args = task_data['args']
                    kwargs = task_data['kwargs']
                    
                    func(*args, **kwargs)
                    
                except Exception as e:
                    self.logger.error(f"Error executing immediate task: {e}")
                finally:
                    self.immediate_queue.task_done()
                    
            except Exception as e:
                self.logger.error(f"Error in worker loop: {e}")
                time.sleep(1)
    
    def _execute_task_safe(self, task: ScheduledTask):
        """Safely execute a task"""
        try:
            self.logger.debug(f"⏰ Executing task: {task.task_id}")
            task.execute()
            
        except Exception as e:
            self.logger.error(f"Task execution error {task.task_id}: {e}")
    
    def _cleanup_completed_tasks(self):
        """Remove completed tasks from memory"""
        try:
            completed_tasks = [task_id for task_id, task in self.tasks.items() 
                             if task.is_completed()]
            
            for task_id in completed_tasks:
                del self.tasks[task_id]
                
            if completed_tasks:
                self.logger.debug(f"🧹 Cleaned up {len(completed_tasks)} completed tasks")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up tasks: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics"""
        try:
            with self.task_lock:
                total_tasks = len(self.tasks)
                running_tasks = sum(1 for task in self.tasks.values() if task.is_running)
                completed_tasks = sum(1 for task in self.tasks.values() if task.is_completed())
                
                return {
                    'running': self.running,
                    'total_tasks': total_tasks,
                    'running_tasks': running_tasks,
                    'completed_tasks': completed_tasks,
                    'pending_tasks': total_tasks - running_tasks - completed_tasks,
                    'immediate_queue_size': self.immediate_queue.qsize(),
                    'worker_threads': len(self.worker_threads)
                }
                
        except Exception as e:
            self.logger.error(f"Error getting stats: {e}")
            return {'error': str(e)}
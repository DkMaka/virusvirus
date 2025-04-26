import os
import psutil
import platform
import logging
import datetime
from app import db
from models import SystemHealthLog

logger = logging.getLogger(__name__)

class SystemMonitor:
    def __init__(self):
        self.suspicious_process_names = [
            'cryptominer',
            'miner',
            'xmrig',
            'nscript',
            'hidden',
            'backdoor',
            'trojan'
        ]
    
    def get_system_status(self):
        """
        Get current system status and health information
        """
        try:
            # Get CPU info
            cpu_usage = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                cpu_freq = cpu_freq.current
            else:
                cpu_freq = 0
            
            # Get memory info
            memory = psutil.virtual_memory()
            memory_total = memory.total / (1024 * 1024 * 1024)  # GB
            memory_used = memory.used / (1024 * 1024 * 1024)  # GB
            memory_percent = memory.percent
            
            # Get disk info
            disks = []
            for partition in psutil.disk_partitions():
                if os.name == 'nt' and ('cdrom' in partition.opts or partition.fstype == ''):
                    # Skip CD-ROM drives on Windows
                    continue
                
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_gb': usage.total / (1024 * 1024 * 1024),
                        'used_gb': usage.used / (1024 * 1024 * 1024),
                        'percent': usage.percent
                    })
                except Exception:
                    continue
            
            # Get system info
            system_info = {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Get process info
            processes = []
            suspicious_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    is_suspicious = any(susp_name in proc_info['name'].lower() for susp_name in self.suspicious_process_names)
                    
                    if is_suspicious:
                        suspicious_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'username': proc_info['username'],
                            'memory_percent': proc_info['memory_percent'],
                            'cpu_percent': proc_info['cpu_percent']
                        })
                    
                    # Only include top processes by CPU or memory usage
                    if proc_info['cpu_percent'] > 5 or proc_info['memory_percent'] > 1:
                        processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'username': proc_info['username'],
                            'memory_percent': proc_info['memory_percent'],
                            'cpu_percent': proc_info['cpu_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sort processes by CPU usage
            processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]
            
            # Get network info
            network_connections = len(psutil.net_connections())
            network_io = psutil.net_io_counters()
            network = {
                'total_connections': network_connections,
                'bytes_sent': network_io.bytes_sent,
                'bytes_recv': network_io.bytes_recv,
                'packets_sent': network_io.packets_sent,
                'packets_recv': network_io.packets_recv
            }
            
            # Log system health
            self._log_system_health(
                cpu_usage, 
                memory_percent, 
                disks[0]['percent'] if disks else 0,
                len(processes),
                len(suspicious_processes),
                network_connections,
                0  # Suspicious connections not implemented
            )
            
            # Return combined status
            return {
                'cpu': {
                    'usage_percent': cpu_usage,
                    'count': cpu_count,
                    'frequency_mhz': cpu_freq
                },
                'memory': {
                    'total_gb': memory_total,
                    'used_gb': memory_used,
                    'percent': memory_percent
                },
                'disks': disks,
                'system': system_info,
                'processes': {
                    'total': len(psutil.pids()),
                    'top_processes': processes,
                    'suspicious_processes': suspicious_processes
                },
                'network': network,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        except Exception as e:
            logger.error(f"Error getting system status: {str(e)}")
            return {
                'error': str(e),
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    
    def _log_system_health(self, cpu_usage, memory_usage, disk_usage, running_processes, 
                         suspicious_processes, network_connections, suspicious_connections):
        """
        Log system health to database
        """
        try:
            # Import app here to avoid circular imports
            from app import app
            
            # Use application context for database operations
            with app.app_context():
                health_log = SystemHealthLog(
                    cpu_usage=cpu_usage,
                    memory_usage=memory_usage,
                    disk_usage=disk_usage,
                    running_processes=running_processes,
                    suspicious_processes=suspicious_processes,
                    network_connections=network_connections,
                    suspicious_connections=suspicious_connections
                )
                db.session.add(health_log)
                db.session.commit()
        except Exception as e:
            logger.error(f"Error logging system health: {str(e)}")

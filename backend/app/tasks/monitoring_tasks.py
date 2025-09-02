"""
Background tasks for host monitoring
"""
import logging
from celery import Celery
from ..database import get_db
from ..services.host_monitor import host_monitor

logger = logging.getLogger(__name__)

def periodic_host_monitoring():
    """
    Periodic task to monitor all hosts
    This can be called by Celery or a scheduler like cron
    """
    try:
        logger.info("Starting periodic host monitoring...")
        
        # Get database session
        db = next(get_db())
        
        # Monitor all hosts
        import asyncio
        results = asyncio.run(host_monitor.monitor_all_hosts(db))
        
        # Log results
        online_count = sum(1 for r in results if r['status'] == 'online')
        total_count = len(results)
        
        logger.info(f"Host monitoring completed: {online_count}/{total_count} hosts online")
        
        # Log any status changes
        for result in results:
            if result.get('error_message'):
                logger.warning(f"Host {result['hostname']} ({result['ip_address']}): {result['error_message']}")
        
        db.close()
        return f"Monitored {total_count} hosts, {online_count} online"
        
    except Exception as e:
        logger.error(f"Error in periodic host monitoring: {e}")
        return f"Error: {str(e)}"

# Example function to set up periodic monitoring with APScheduler
def setup_host_monitoring_scheduler():
    """
    Set up periodic host monitoring using APScheduler
    This only creates the scheduler instance - jobs are configured by restore_scheduler_state()
    """
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        import atexit
        
        scheduler = BackgroundScheduler()
        
        # Don't auto-start or add jobs here - let restore_scheduler_state() handle it
        # This allows database configuration to control the scheduler behavior
        logger.info("Host monitoring scheduler instance created (not started)")
        
        # Shut down the scheduler when exiting the app
        atexit.register(lambda: scheduler.shutdown())
        
        return scheduler
        
    except ImportError:
        logger.warning("APScheduler not available, periodic monitoring disabled")
        return None
    except Exception as e:
        logger.error(f"Failed to setup monitoring scheduler: {e}")
        return None
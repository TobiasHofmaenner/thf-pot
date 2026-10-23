import logging

from celery import shared_task

log = logging.getLogger(__name__)


@shared_task
def ping():
    """Round-trip through the broker; the status page uses it to prove a worker is alive."""
    return "pong"


@shared_task
def heartbeat():
    """Beat fires this every minute so the schedule path is exercised from day one."""
    log.info("heartbeat")
    return "ok"

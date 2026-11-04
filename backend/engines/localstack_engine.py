"""
LocalStack AWS Engine & Cloud Connector Bridge
==============================================
Provides backward compatibility for existing callers while delegating
to the unified cloud_connector engine supporting real AWS STS and LocalStack.
"""
import os
from typing import Dict, Any, List

from engines.cloud_connector import (
    LOCALSTACK_ENDPOINT,
    is_localstack_running,
    get_cloud_client,
    run_production_cspm_scan,
    run_production_ciem_scan,
    get_localstack_status as _get_status,
    probe_cloud_connectivity
)

USE_LOCALSTACK = os.environ.get("USE_LOCALSTACK", "false").lower() == "true"


def _client(service: str):
    return get_cloud_client(service)


def run_cspm_scan_localstack() -> list:
    """Executes CSPM scan via cloud connector (LocalStack or Live AWS)."""
    return run_production_cspm_scan()


def run_ciem_scan_localstack() -> list:
    """Executes CIEM scan via cloud connector (LocalStack or Live AWS)."""
    return run_production_ciem_scan()


def get_localstack_status() -> dict:
    """Returns status dictionary of the active cloud/emulation connection."""
    return _get_status()

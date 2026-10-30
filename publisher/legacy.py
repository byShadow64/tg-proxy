"""Load the single shared SFTP publication implementation in source/frozen apps."""
from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path

_LOCK = threading.RLock()


def publication_core():
    with _LOCK:
        return _load_publication_core()


def _load_publication_core():
    name = "_tgproxy_shared_publication"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "packaging" / "publish_updates.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Publisher component is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module

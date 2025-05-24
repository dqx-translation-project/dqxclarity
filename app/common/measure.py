from functools import wraps
from loguru import logger

import inspect
import time


def measure_duration(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # get function metadata
        name = func.__name__
        module = func.__module__
        line = inspect.getsourcelines(func)[1]

        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        logger.debug(f"[{module}.{name}:{line}] Execution took {duration:.6f} seconds")
        return result
    return wrapper

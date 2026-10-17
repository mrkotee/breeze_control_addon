"""Process-scoped Windows idle-sleep hold for attended hardware proofs."""
import ctypes
import os


class SystemAwake:
    def __init__(self):
        self._call = None
        self._previous = None

    def acquire(self):
        if self._previous is not None:
            return
        if os.name != 'nt':
            raise RuntimeError('Windows proof power hold requires Windows')
        call = ctypes.WinDLL('kernel32', use_last_error=True).SetThreadExecutionState
        call.argtypes = [ctypes.c_uint32]
        call.restype = ctypes.c_uint32
        previous = call(0x80000001)  # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
        if not previous:
            raise ctypes.WinError(ctypes.get_last_error())
        self._call, self._previous = call, previous

    def close(self):
        if self._previous is None:
            return True
        if not self._call(self._previous | 0x80000000):
            return False
        self._previous = None
        return True

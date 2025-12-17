from pathlib import Path
import tempfile
from src.interpreter import run_program


def run_binary_bytes(binary_bytes: bytes, data_mem_size: int = 1<<16, regs_count: int = 32):
    with tempfile.NamedTemporaryFile(prefix="uvm_", suffix=".bin", delete=False) as tf:
        tf.write(binary_bytes)
        tmp_path = Path(tf.name)

    try:
        state = run_program(str(tmp_path), data_mem_size=data_mem_size, regs_count=regs_count, dump_csv=None, dump_range=None)
        return state
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass

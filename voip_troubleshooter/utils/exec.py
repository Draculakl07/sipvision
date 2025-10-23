"""Subprocess execution helpers with streaming output."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from queue import Empty, Queue
from typing import Iterator, List, Tuple


_REDAC_TABLE: List[str] = [name for name in os.environ if any(token in name.upper() for token in ("API", "TOKEN", "KEY"))]


def _redact_message(message: str) -> str:
    """Redact potential secrets from a message."""
    redacted = message
    for name in _REDAC_TABLE:
        value = os.environ.get(name)
        if value:
            redacted = redacted.replace(value, "***")
    return redacted


def run_cmd(cmd: List[str], timeout: int) -> Tuple[int, Iterator[str]]:
    """Run a command with a timeout, streaming stdout line by line.

    Args:
        cmd: Command arguments.
        timeout: Seconds before the subprocess is terminated.

    Returns:
        A tuple of (exit_code, iterator_over_stdout_lines).
    """

    if not cmd:
        raise ValueError("Command must not be empty")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    output_queue: "Queue[object]" = Queue()
    sentinel = object()

    def _reader() -> None:
        try:
            assert process.stdout is not None
            for line in iter(process.stdout.readline, ""):
                output_queue.put(line.rstrip("\n"))
        except Exception as exc:  # pragma: no cover - defensive
            output_queue.put(_redact_message(f"[reader-error] {exc}"))
        finally:
            output_queue.put(sentinel)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    timed_out = False
    deadline = time.monotonic() + timeout if timeout else None

    lines: List[str] = []

    while True:
        try:
            item = output_queue.get(timeout=0.1)
        except Empty:
            item = None

        if item is None:
            if deadline and time.monotonic() > deadline and process.poll() is None:
                timed_out = True
                try:
                    process.terminate()
                except Exception:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        if sys.platform.startswith("win"):
                            process.kill()
                        else:
                            os.kill(process.pid, signal.SIGKILL)
                    except Exception:
                        process.kill()
                continue
        elif item is sentinel:
            break
        else:
            lines.append(str(item))

    reader_thread.join(timeout=1)
    exit_code = process.wait()

    if timed_out:
        exit_code = exit_code if exit_code is not None else -signal.SIGTERM

    def _iter_lines() -> Iterator[str]:
        for line in lines:
            yield line

    return exit_code, _iter_lines()


__all__ = ["run_cmd"]

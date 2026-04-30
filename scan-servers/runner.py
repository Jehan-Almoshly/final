import os
import signal
import subprocess
import threading
import time
import re

PROGRESS_PATTERN = re.compile(r"::\s*Progress:\s*\[")


# =============================================================================
# Process registry for pause/resume support.
# Each tool API server (nmap_api, nikto_api, sqlmap_api, ffuf_api) imports
# run_streaming and shares this registry. Keys are scan_id strings (provided
# by the gateway when it dispatches a scan); values are the live Popen handle.
# =============================================================================

_RUNNING: dict[str, subprocess.Popen] = {}
_PAUSED: set[str] = set()
_REGISTRY_LOCK = threading.Lock()


def _register(scan_id: str, proc: subprocess.Popen):
    with _REGISTRY_LOCK:
        _RUNNING[scan_id] = proc


def _unregister(scan_id: str):
    with _REGISTRY_LOCK:
        _RUNNING.pop(scan_id, None)
        _PAUSED.discard(scan_id)


def pause_process(scan_id: str) -> tuple[bool, str]:
    """SIGSTOP the process group for the given scan_id.
    Returns (ok, message)."""
    with _REGISTRY_LOCK:
        proc = _RUNNING.get(scan_id)
    if not proc:
        return False, "scan not found in this process"
    if proc.poll() is not None:
        return False, "scan has already finished"
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGSTOP)
    except ProcessLookupError:
        return False, "process no longer exists"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    with _REGISTRY_LOCK:
        _PAUSED.add(scan_id)
    return True, "paused"


def resume_process(scan_id: str) -> tuple[bool, str]:
    """SIGCONT the process group for the given scan_id."""
    with _REGISTRY_LOCK:
        proc = _RUNNING.get(scan_id)
    if not proc:
        return False, "scan not found in this process"
    if proc.poll() is not None:
        return False, "scan has already finished"
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGCONT)
    except ProcessLookupError:
        return False, "process no longer exists"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    with _REGISTRY_LOCK:
        _PAUSED.discard(scan_id)
    return True, "resumed"


def is_paused(scan_id: str) -> bool:
    with _REGISTRY_LOCK:
        return scan_id in _PAUSED


def run_streaming(
    cmd: list,
    timeout: int,
    label: str = "TOOL",
    scan_id: str | None = None,
) -> tuple[str, int]:
    """
    Run a command, streaming each output line live to the terminal (stdout)
    while also collecting the full output to return.
    Handles both \\n and \\r line endings (e.g. FFUF progress bar).

    If `scan_id` is provided, the underlying Popen is registered so external
    callers can pause/resume it via pause_process()/resume_process().

    The timeout clock excludes time spent paused (we adjust the deadline
    while the process is in SIGSTOP state).

    Returns (combined_output, return_code).
    """
    start = time.time()
    print(f"\n{'=' * 70}", flush=True)
    print(f"[{label}] Starting: {' '.join(cmd)}", flush=True)
    if scan_id:
        print(f"[{label}] scan_id={scan_id}", flush=True)
    print(f"{'=' * 70}", flush=True)

    try:
        # start_new_session=True puts the child in its own process group,
        # so SIGSTOP/SIGCONT delivered via killpg() reaches the tool *and*
        # any sub-processes it spawns (e.g. nmap NSE scripts).
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            start_new_session=True,
        )
    except FileNotFoundError as e:
        msg = f"[{label}] Command not found: {e}"
        print(msg, flush=True)
        return msg, 127

    if scan_id:
        _register(scan_id, proc)

    collected_lines: list[str] = []
    last_progress = ""

    def reader():
        nonlocal last_progress
        assert proc.stdout is not None
        buf = b""
        try:
            while True:
                chunk = proc.stdout.read(512)
                if not chunk:
                    break
                buf += chunk
                while True:
                    nl = buf.find(b"\n")
                    cr = buf.find(b"\r")
                    if nl == -1 and cr == -1:
                        break
                    if nl == -1:
                        sep, end = cr, cr + 1
                    elif cr == -1:
                        sep, end = nl, nl + 1
                    else:
                        sep, end = (nl, nl + 1) if nl < cr else (cr, cr + 1)

                    raw_line = buf[:sep].decode("utf-8", errors="replace").strip()
                    buf = buf[end:]

                    if not raw_line:
                        continue

                    if PROGRESS_PATTERN.search(raw_line):
                        last_progress = raw_line
                        continue

                    collected_lines.append(raw_line)
                    print(f"[{label}] {raw_line}", flush=True)

            if buf:
                raw_line = buf.decode("utf-8", errors="replace").strip()
                if raw_line and not PROGRESS_PATTERN.search(raw_line):
                    collected_lines.append(raw_line)
                    print(f"[{label}] {raw_line}", flush=True)

        except Exception as e:
            collected_lines.append(f"[reader error] {e}")

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # Wait loop that respects pauses: while the scan is paused we keep
    # extending the deadline (paused time doesn't count against timeout).
    deadline = start + timeout
    paused_total = 0.0
    timed_out = False
    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                if scan_id and is_paused(scan_id):
                    # Don't time out while paused — just wait a bit.
                    time.sleep(1)
                    deadline += 1
                    paused_total += 1
                    continue
                timed_out = True
                break

            # Short poll so we can react to pauses/resumes promptly.
            try:
                proc.wait(timeout=min(remaining, 1.0))
                break  # finished
            except subprocess.TimeoutExpired:
                if scan_id and is_paused(scan_id):
                    deadline += 1
                    paused_total += 1
                continue
    except Exception:
        pass

    if timed_out:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGCONT)
        except Exception:
            pass
        proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        t.join(timeout=5)
        if scan_id:
            _unregister(scan_id)
        elapsed = int(time.time() - start)
        if last_progress:
            print(f"[{label}] Last progress: {last_progress}", flush=True)
        msg = (
            f"\n[{label}] TIMEOUT after {elapsed}s "
            f"(limit {timeout}s, paused for ~{int(paused_total)}s)"
        )
        print(msg, flush=True)
        collected_lines.append(msg)
        return "\n".join(collected_lines), -1

    t.join(timeout=10)
    if scan_id:
        _unregister(scan_id)
    elapsed = int(time.time() - start)
    rc = proc.returncode

    if last_progress:
        print(f"[{label}] {last_progress}", flush=True)

    print(
        f"\n[{label}] Finished in {elapsed}s "
        f"(paused ~{int(paused_total)}s) with exit code {rc}",
        flush=True,
    )
    print(f"[{label}] Total output lines: {len(collected_lines)}", flush=True)
    print(f"{'=' * 70}\n", flush=True)

    return "\n".join(collected_lines), rc

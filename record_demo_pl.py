r"""Record a 1920x1080 ~120s demo video of ASI Mini for Polish narration.

Not committed to git (per instructions). Requires: playwright + chromium.
Usage: .\.venv\Scripts\python.exe record_demo_pl.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
OUT_DIR = REPO / "demo_out"
PY = str(REPO / ".venv" / "Scripts" / "python.exe")
PORT = 8001
BASE = f"http://127.0.0.1:{PORT}"

# Global process handles so finally can kill them.
_procs: list[subprocess.Popen] = []


def wait_health(timeout: float = 40.0) -> bool:
    """Poll /api/health until 200 or timeout."""
    import json
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE}/api/health", timeout=2.0) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def start_servers() -> None:
    """Start lab_sim.py and uvicorn as background subprocesses."""
    OUT_DIR.mkdir(exist_ok=True)

    lab = subprocess.Popen(
        [PY, str(REPO / "lab_sim.py")],
        cwd=str(REPO),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _procs.append(lab)

    uv = subprocess.Popen(
        [PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=str(REPO),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "ASI_DATA_DIR": str(OUT_DIR / "demo_data")},
    )
    _procs.append(uv)

    if not wait_health():
        raise RuntimeError("uvicorn did not become healthy on port 8001")


def stop_servers() -> None:
    for p in reversed(_procs):
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


async def record() -> str:
    from playwright.async_api import async_playwright

    video_path = None
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            record_video_dir=str(OUT_DIR),
            record_video_size={"width": 1920, "height": 1080},
        )
        page = await context.new_page()
        await page.goto(BASE, wait_until="domcontentloaded")

        # ---------------------------------------------------------------
        # Scene 1 — Dashboard, graf i dowód Fernet AES (0:00–0:30)
        # ---------------------------------------------------------------
        # Login as admin
        await page.click("#loginModal button:has-text('admin / admin123')")
        await page.click("#loginModal button[type='submit']")
        await page.wait_for_selector("text=Administracja", timeout=10000)
        await page.wait_for_timeout(4000)

        # Demo Run 2
        await page.click("button:has-text('Demo Run 2')")
        await page.wait_for_timeout(6000)

        # Fit view
        try:
            await page.click("button:has-text('Fit view')", timeout=3000)
        except Exception:
            pass
        await page.wait_for_timeout(3000)

        # Scroll to tech chips + asset inventory, click a chip, reset
        try:
            await page.hover("#techTags .chip", timeout=4000)
            await page.wait_for_timeout(1500)
            # click first chip
            await page.click("#techTags .chip", timeout=3000)
            await page.wait_for_timeout(3000)
            # reset filter via the tech summary or Fit view
            await page.evaluate("document.querySelectorAll('#techTags .chip')[0].click()")
            await page.wait_for_timeout(2000)
        except Exception:
            pass
        await page.wait_for_timeout(2000)

        # Scroll back up and click Fernet AES badge -> proof modal
        await page.evaluate("window.scrollTo(0, 0)")
        await page.wait_for_timeout(800)
        try:
            await page.click("#encBadge", timeout=3000)
            await page.wait_for_selector("#encProofModal:not(.hidden)", timeout=4000)
            await page.wait_for_timeout(10000)  # hold for narration
            await page.click("#encProofModal .btn-ghost")
        except Exception:
            pass

        # ---------------------------------------------------------------
        # Scene 2 — Skalowanie >10k IP i skan wieloportowy na żywo (0:30–1:05)
        # ---------------------------------------------------------------
        await page.click("button:has-text('Scanner')")
        await page.wait_for_timeout(3000)

        # 10.0.0.0/18 plan
        await page.fill("#targetsInput", "10.0.0.0/18")
        await page.click("button:has-text('Calculate Plan')")
        await page.wait_for_timeout(8000)

        # Live multi-port scan against lab_sim (run twice)
        await page.fill("#targetsInput", "127.0.0.1")
        try:
            await page.check("#scanPorts")
        except Exception:
            pass
        await page.fill("#allowedPorts", "9001,9002,9003")

        # Run scan 1
        await page.click("button:has-text('Run Discovery Scan')")
        await page.wait_for_timeout(8000)
        # Run scan 2
        await page.click("button:has-text('Run Discovery Scan')")
        await page.wait_for_timeout(8000)

        # ---------------------------------------------------------------
        # Scene 3 — Oś czasu SVG, diff i host flaky 9003 (1:05–1:30)
        # ---------------------------------------------------------------
        await page.click("button:has-text('History')")
        await page.wait_for_timeout(10000)  # timeline chart

        # Compare the two newest scans
        try:
            await page.click("button:has-text('Compare')", timeout=3000)
            await page.wait_for_timeout(18000)  # hold for narration
        except Exception:
            await page.wait_for_timeout(10000)

        # ---------------------------------------------------------------
        # Scene 4 — Selektywny eksport Info/Evidence + RBAC auditor (1:30–2:00)
        # ---------------------------------------------------------------
        await page.click("button:has-text('Dashboard')")
        await page.wait_for_timeout(3000)

        # Check 2 findings + toggle evidence
        try:
            cbs = await page.query_selector_all(".finding-cb")
            if len(cbs) >= 2:
                await cbs[0].check()
                await cbs[1].check()
            await page.check("#evidenceToggle")
            await page.wait_for_timeout(8000)
        except Exception:
            pass

        # Logout -> login as auditor
        try:
            await page.click("button:has-text('Wyloguj')")
            await page.wait_for_selector("#loginModal:not(.hidden)", timeout=4000)
        except Exception:
            pass
        await page.fill("#loginUser", "auditor")
        await page.fill("#loginPass", "auditor123")
        await page.click("#loginModal button[type='submit']")
        await page.wait_for_timeout(12000)

        # Click encryption badge as auditor -> blocked toast
        try:
            await page.click("#encBadge", timeout=3000)
            await page.wait_for_timeout(8000)
        except Exception:
            pass

        # Give the video a moment to finalize
        await page.wait_for_timeout(2000)

        video = page.video
        await context.close()
        await browser.close()
        if video:
            video_path = await video.path()

    return video_path


def main() -> int:
    # Ensure playwright chromium is installed
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        print("Playwright not installed. Run:")
        print(r"  .\.venv\Scripts\pip.exe install playwright")
        print(r"  .\.venv\Scripts\playwright.exe install chromium")
        return 1

    start_servers()
    try:
        raw_path = record_sync()
    finally:
        stop_servers()

    if not raw_path or not Path(raw_path).exists():
        print("ERROR: video was not produced")
        return 2

    # Playwright saves as a random .webm inside demo_out; rename to final name.
    final_webm = OUT_DIR / "asi_mini_demo_pl.webm"
    shutil.move(raw_path, final_webm)

    # Optional mp4 conversion if ffmpeg present.
    final_mp4 = OUT_DIR / "asi_mini_demo_pl.mp4"
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg:
        try:
            subprocess.run(
                [ffmpeg, "-y", "-i", str(final_webm), str(final_mp4)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=180,
            )
            print(f"MP4:  {final_mp4}")
        except Exception as e:
            print(f"ffmpeg conversion failed: {e}")

    dur = probe_duration(final_webm)
    print("=" * 60)
    print(f"WEBM: {final_webm}")
    print(f"Duration: {dur:.1f}s" if dur else "Duration: unknown")
    print("=" * 60)
    return 0


def record_sync():
    """Run the async record() from sync main()."""
    import asyncio

    return asyncio.run(record())


def probe_duration(path: Path):
    """Best-effort duration probe via ffprobe, else estimate."""
    ffprobe = shutil.which("ffprobe")
    if ffprobe:
        try:
            out = subprocess.run(
                [ffprobe, "-v", "error", "-show_entries", "format=duration",
                 "-of", "default=noprint_wrappers=1:nokey=1", str(path)],
                capture_output=True, text=True, timeout=30,
            )
            return float(out.stdout.strip())
        except Exception:
            pass
    return None


if __name__ == "__main__":
    sys.exit(main())
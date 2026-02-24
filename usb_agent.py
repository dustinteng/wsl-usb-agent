#!/usr/bin/env python3
"""
usb_agent.py — Layer 2: Python orchestrator for WSL USB Automation
Handles: usbipd calls (via PowerShell), bash layer invocation, checksums, logging
"""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
BASH_SCRIPT = SCRIPT_DIR / "usb_mount.sh"
LOG_DIR = SCRIPT_DIR / "logs"
MOUNT_POINT = "/mnt/usb"

# CivNav image naming: civnav_{MMDDYYYY}_{SW_VER}_{HW_VER}_{UNIT}.img.gz
CIVNAV_PATTERN = re.compile(
    r"^civnav_(\d{8})_(\d+\.\d+\.\d+)_(\d+\.\d+\.\d+)_(\d+)\.img\.gz$"
)

# usbipd list line: BUSID  VID:PID  DEVICE (with spaces)  STATE
# Example: 2-14   21c4:0cd1  USB Mass Storage Device                   Not shared
USBIPD_LINE = re.compile(
    r"^(\d+-\d+)\s+"                    # BUSID
    r"([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\s+"  # VID:PID
    r"(.+?)\s{2,}"                      # DEVICE (greedy until 2+ spaces)
    r"(Not shared|Shared|Attached.*)$"  # STATE
)

LOG_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_file = LOG_DIR / f"usb_agent_{datetime.now():%Y%m%d_%H%M%S}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(log_file)),
    ],
)
log = logging.getLogger("usb_agent")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run(cmd: list[str], check: bool = True, capture: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a command, log it, return result."""
    log.info(f"RUN: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        **kwargs,
    )
    if result.stdout:
        for line in result.stdout.strip().splitlines():
            log.info(f"  stdout: {line}")
    if result.stderr:
        for line in result.stderr.strip().splitlines():
            log.warning(f"  stderr: {line}")
    if check and result.returncode != 0:
        log.error(f"Command failed (rc={result.returncode}): {' '.join(cmd)}")
        sys.exit(1)
    return result


def run_powershell(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Execute a command via PowerShell on Windows host from WSL."""
    return run(["powershell.exe", "-NoProfile", "-Command", cmd], check=check)


def run_bash(subcmd: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Execute usb_mount.sh subcommand."""
    return run(["sudo", "bash", str(BASH_SCRIPT), subcmd, *args], check=check)


def win_to_wsl_path(win_path: str) -> str:
    """Convert a Windows path to WSL path.

    C:\\Users\\Civ Robotics\\file.gz → /mnt/c/Users/Civ Robotics/file.gz
    """
    path = win_path.strip().strip('"').strip("'")
    # Already a Linux path
    if path.startswith("/"):
        return path
    # Convert backslashes
    path = path.replace("\\", "/")
    # Convert drive letter: C:/... → /mnt/c/...
    if len(path) >= 2 and path[1] == ":":
        drive = path[0].lower()
        path = f"/mnt/{drive}{path[2:]}"
    return path


# ---------------------------------------------------------------------------
# USBIPD Integration (Windows ↔ WSL)
# ---------------------------------------------------------------------------
def usbipd_list() -> list[dict]:
    """Parse usbipd list output into structured data."""
    result = run_powershell("usbipd list", check=False)
    if result.returncode != 0:
        log.error("usbipd not found or failed. Is usbipd-win installed?")
        sys.exit(1)

    devices = []
    for line in result.stdout.splitlines():
        line = line.strip()
        # Skip header/separator/section lines
        if not line or line.startswith("BUSID") or line.startswith("---"):
            continue
        if line.startswith("Connected") or line.startswith("Persisted") or line.startswith("GUID"):
            continue

        # Use regex to properly parse lines with multi-word device names
        match = USBIPD_LINE.match(line)
        if match:
            busid, vidpid, description, state = match.groups()
            devices.append({
                "busid": busid,
                "vidpid": vidpid,
                "description": description.strip(),
                "state": state.strip(),
            })
            log.info(f"  Device: {busid}  {vidpid}  {description.strip()}  [{state.strip()}]")

    if not devices:
        log.warning("No devices parsed from usbipd list")

    return devices


def find_usb_mass_storage(devices: list[dict]) -> dict | None:
    """Find a USB mass storage device from usbipd list."""
    keywords = ["mass storage", "usb storage", "disk", "flash", "sandisk", "kingston", "samsung"]
    for dev in devices:
        desc_lower = dev["description"].lower()
        if any(kw in desc_lower for kw in keywords):
            log.info(f"Found USB storage: {dev['busid']} — {dev['description']} [{dev['state']}]")
            return dev

    # Fallback: show all and let user know
    log.warning("Could not auto-detect USB mass storage. Devices found:")
    for dev in devices:
        log.warning(f"  {dev['busid']}  {dev['description']}  [{dev['state']}]")
    return None


def usbipd_bind(busid: str) -> None:
    """Bind a USB device (requires admin on Windows)."""
    log.info(f"Binding USB device {busid}...")
    run_powershell(f"usbipd bind --busid {busid}", check=False)


def usbipd_attach(busid: str) -> None:
    """Attach a USB device to WSL."""
    log.info(f"Attaching USB device {busid} to WSL...")
    result = run_powershell(f"usbipd attach --wsl --busid {busid}", check=False)
    if result.returncode != 0:
        # May need bind first
        log.warning("Attach failed — trying bind first...")
        usbipd_bind(busid)
        time.sleep(2)
        run_powershell(f"usbipd attach --wsl --busid {busid}")
    # Give WSL time to recognize the device
    log.info("Waiting for WSL to detect device...")
    time.sleep(3)


def usbipd_detach(busid: str) -> None:
    """Detach USB device from WSL."""
    log.info(f"Detaching USB device {busid}...")
    run_powershell(f"usbipd detach --busid {busid}", check=False)
    log.info("Device detached")


# ---------------------------------------------------------------------------
# File Operations
# ---------------------------------------------------------------------------
def sha256_file(filepath: str) -> str:
    """Compute SHA256 hash of a file."""
    log.info(f"Computing SHA256 for: {filepath}")
    h = hashlib.sha256()
    size = os.path.getsize(filepath)
    read_bytes = 0
    last_pct = -1

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)  # 8MB chunks
            if not chunk:
                break
            h.update(chunk)
            read_bytes += len(chunk)
            pct = int(read_bytes * 100 / size) if size > 0 else 100
            if pct >= last_pct + 10:
                log.info(f"  Hashing... {pct}%")
                last_pct = pct

    digest = h.hexdigest()
    log.info(f"  SHA256: {digest}")
    return digest


def copy_file(src: str, dst: str) -> None:
    """Copy file using rsync with progress and resume support."""
    log.info(f"Copying: {src} → {dst}")

    # Ensure destination directory exists
    dst_dir = os.path.dirname(dst)
    if dst_dir:
        os.makedirs(dst_dir, exist_ok=True)

    run(
        ["rsync", "-ah", "--progress", "--partial", "--info=progress2", src, dst],
        capture=False,  # Let progress output show in terminal
    )
    log.info("Copy complete")


def verify_copy(src: str, dst: str) -> bool:
    """Verify source and destination match via SHA256."""
    log.info("Verifying file integrity...")
    src_hash = sha256_file(src)
    dst_hash = sha256_file(dst)

    if src_hash == dst_hash:
        log.info(f"VERIFIED: checksums match ({src_hash[:16]}...)")
        return True
    else:
        log.error(f"MISMATCH: src={src_hash[:16]}... dst={dst_hash[:16]}...")
        return False


# ---------------------------------------------------------------------------
# CivNav Image Helpers
# ---------------------------------------------------------------------------
def parse_civnav_name(filename: str) -> dict | None:
    """Parse a CivNav image filename into its components.

    Format: civnav_{MMDDYYYY}_{SW_VER}_{HW_VER}_{UNIT}.img.gz
    Example: civnav_02232026_1.2.9_2.1.1_003.img.gz
    """
    basename = os.path.basename(filename)
    match = CIVNAV_PATTERN.match(basename)
    if not match:
        return None

    date_str, sw_ver, hw_ver, unit = match.groups()
    return {
        "filename": basename,
        "date": date_str,
        "date_formatted": f"{date_str[:2]}/{date_str[2:4]}/{date_str[4:]}",
        "sw_version": sw_ver,
        "hw_version": hw_ver,
        "unit": unit,
        "unit_int": int(unit),
    }


def find_civnav_images(search_dir: str) -> list[dict]:
    """Scan a directory for CivNav .img.gz files and return parsed metadata."""
    images = []
    try:
        for entry in os.scandir(search_dir):
            if not entry.is_file():
                continue
            parsed = parse_civnav_name(entry.name)
            if parsed:
                parsed["path"] = entry.path
                parsed["size_bytes"] = entry.stat().st_size
                parsed["size_human"] = _human_size(entry.stat().st_size)
                images.append(parsed)
        # Sort: newest date first, then highest unit number
        images.sort(key=lambda x: (x["date"], x["unit_int"]), reverse=True)
    except OSError as e:
        log.warning(f"Could not scan {search_dir}: {e}")
    return images


def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"


def print_civnav_table(images: list[dict]) -> None:
    """Pretty-print a table of discovered CivNav images."""
    if not images:
        log.info("  (no CivNav images found)")
        return
    log.info(f"  {'#':<4} {'Filename':<50} {'Size':<10} {'SW':<8} {'HW':<8} {'Unit':<6} {'Date'}")
    log.info(f"  {'─'*4} {'─'*50} {'─'*10} {'─'*8} {'─'*8} {'─'*6} {'─'*12}")
    for i, img in enumerate(images):
        log.info(
            f"  {i:<4} {img['filename']:<50} {img['size_human']:<10} "
            f"{img['sw_version']:<8} {img['hw_version']:<8} {img['unit']:<6} {img['date_formatted']}"
        )


# ---------------------------------------------------------------------------
# High-Level Workflows
# ---------------------------------------------------------------------------
def workflow_from_usb(filename: str, dest_dir: str, skip_verify: bool = False) -> None:
    """Copy a file FROM the USB to the local filesystem."""
    log.info("=" * 60)
    log.info(f"WORKFLOW: Copy FROM USB → local")
    log.info(f"  File: {filename}")
    log.info(f"  Dest: {dest_dir}")
    log.info("=" * 60)

    # Step 1: Detect and attach via usbipd
    devices = usbipd_list()
    usb_dev = find_usb_mass_storage(devices)
    if not usb_dev:
        log.error("No USB storage device found. Plug in a USB drive and try again.")
        sys.exit(1)

    busid = usb_dev["busid"]
    state = usb_dev["state"].lower()

    if "attached" not in state:
        usbipd_attach(busid)
    else:
        log.info("Device already attached to WSL")

    # Step 2: Mount via bash layer
    run_bash("mount")

    # Step 3: Find the file on USB
    src_path = os.path.join(MOUNT_POINT, filename)
    if not os.path.exists(src_path):
        # Try searching subdirectories
        log.warning(f"File not found at {src_path}, searching...")
        result = run(
            ["find", MOUNT_POINT, "-name", filename, "-type", "f"],
            check=False,
        )
        found = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
        if found:
            src_path = found[0]
            log.info(f"Found file at: {src_path}")
        else:
            # Show available CivNav images to help the user
            log.error(f"File '{filename}' not found on USB")
            log.info("Scanning for CivNav images on USB...")
            images = find_civnav_images(MOUNT_POINT)
            # Also check one level of subdirectories
            try:
                for entry in os.scandir(MOUNT_POINT):
                    if entry.is_dir():
                        images.extend(find_civnav_images(entry.path))
            except OSError:
                pass
            if images:
                log.info("Available CivNav images:")
                print_civnav_table(images)
            else:
                run_bash("list")
            teardown(busid)
            sys.exit(1)

    # Step 4: Copy
    dst_path = os.path.join(dest_dir, os.path.basename(src_path))
    copy_file(src_path, dst_path)

    # Step 5: Verify
    if skip_verify:
        log.info("Skipping verification (--skip-verify)")
    elif not verify_copy(src_path, dst_path):
        log.error("INTEGRITY CHECK FAILED — file may be corrupted!")
        teardown(busid)
        sys.exit(1)

    # Step 6: Teardown
    teardown(busid)
    log.info("=" * 60)
    log.info(f"SUCCESS: {filename} → {dst_path}")
    # Log parsed CivNav metadata if applicable
    parsed = parse_civnav_name(filename)
    if parsed:
        log.info(f"  Date: {parsed['date_formatted']}  SW: {parsed['sw_version']}  HW: {parsed['hw_version']}  Unit: {parsed['unit']}")
    log.info("=" * 60)


def workflow_to_usb(filepath: str, usb_dest: str = "", skip_verify: bool = False) -> None:
    """Copy a file TO the USB from the local/Windows filesystem.

    Args:
        filepath: Source path (Windows or WSL path — auto-converted)
        usb_dest: Subdirectory on USB relative to mount point (e.g. "home/compulab")
        skip_verify: Skip SHA256 check
    """
    # Auto-convert Windows paths
    filepath = win_to_wsl_path(filepath)

    log.info("=" * 60)
    log.info(f"WORKFLOW: Copy TO USB ← local")
    log.info(f"  Source: {filepath}")
    if usb_dest:
        log.info(f"  USB dest: {MOUNT_POINT}/{usb_dest}")
    log.info("=" * 60)

    if not os.path.exists(filepath):
        log.error(f"Source file not found: {filepath}")
        log.error("If this is a Windows path, make sure the drive is accessible in WSL.")
        log.error(f"  Tried: {filepath}")
        sys.exit(1)

    src_size = os.path.getsize(filepath)
    log.info(f"Source file size: {_human_size(src_size)}")

    # Step 1: Detect and attach
    devices = usbipd_list()
    usb_dev = find_usb_mass_storage(devices)
    if not usb_dev:
        log.error("No USB storage device found.")
        sys.exit(1)

    busid = usb_dev["busid"]
    state = usb_dev["state"].lower()

    if "attached" not in state:
        usbipd_attach(busid)
    else:
        log.info("Device already attached to WSL")

    # Step 2: Mount
    run_bash("mount")

    # Step 3: Determine destination path on USB
    if usb_dest:
        dest_dir = os.path.join(MOUNT_POINT, usb_dest.strip("/"))
    else:
        dest_dir = MOUNT_POINT

    # Verify the destination directory exists on USB
    if not os.path.isdir(dest_dir):
        log.warning(f"Destination directory does not exist: {dest_dir}")
        log.info(f"Creating: {dest_dir}")
        run(["sudo", "mkdir", "-p", dest_dir])

    dst_path = os.path.join(dest_dir, os.path.basename(filepath))

    # Check if file already exists on USB
    if os.path.exists(dst_path):
        existing_size = os.path.getsize(dst_path)
        log.warning(f"File already exists on USB: {dst_path} ({_human_size(existing_size)})")
        log.info("rsync will overwrite/update it")

    # Step 4: Copy
    copy_file(filepath, dst_path)

    # Step 5: Verify
    if skip_verify:
        log.info("Skipping verification (--skip-verify)")
    elif not verify_copy(filepath, dst_path):
        log.error("INTEGRITY CHECK FAILED — file may be corrupted!")
        teardown(busid)
        sys.exit(1)

    # Step 6: Teardown
    teardown(busid)
    log.info("=" * 60)
    log.info(f"SUCCESS: {filepath}")
    log.info(f"     →   {dst_path}")
    parsed = parse_civnav_name(os.path.basename(filepath))
    if parsed:
        log.info(f"  Date: {parsed['date_formatted']}  SW: {parsed['sw_version']}  HW: {parsed['hw_version']}  Unit: {parsed['unit']}")
    log.info("=" * 60)


def workflow_list_images(busid_override: str | None = None) -> None:
    """Mount USB and list all CivNav images found."""
    devices = usbipd_list()
    usb_dev = find_usb_mass_storage(devices)
    if not usb_dev:
        log.error("No USB storage device found.")
        sys.exit(1)

    busid = busid_override or usb_dev["busid"]
    if "attached" not in usb_dev["state"].lower():
        usbipd_attach(busid)

    run_bash("mount")

    log.info("Scanning USB for CivNav images...")
    images = find_civnav_images(MOUNT_POINT)
    # Check one level of subdirectories too
    try:
        for entry in os.scandir(MOUNT_POINT):
            if entry.is_dir():
                images.extend(find_civnav_images(entry.path))
    except OSError:
        pass

    print_civnav_table(images)

    if not images:
        log.info("No CivNav images found. All files on USB:")
        run_bash("list")

    teardown(busid)


def workflow_latest_from_usb(dest_dir: str, unit: str | None = None) -> None:
    """Auto-detect and copy the latest CivNav image from USB."""
    log.info("=" * 60)
    log.info("WORKFLOW: Copy LATEST CivNav image FROM USB")
    log.info("=" * 60)

    devices = usbipd_list()
    usb_dev = find_usb_mass_storage(devices)
    if not usb_dev:
        log.error("No USB storage device found.")
        sys.exit(1)

    busid = usb_dev["busid"]
    if "attached" not in usb_dev["state"].lower():
        usbipd_attach(busid)

    run_bash("mount")

    images = find_civnav_images(MOUNT_POINT)
    try:
        for entry in os.scandir(MOUNT_POINT):
            if entry.is_dir():
                images.extend(find_civnav_images(entry.path))
    except OSError:
        pass

    if not images:
        log.error("No CivNav images found on USB")
        teardown(busid)
        sys.exit(1)

    # Filter by unit if specified
    if unit:
        filtered = [img for img in images if img["unit"] == unit.zfill(3) or img["unit"] == unit]
        if not filtered:
            log.error(f"No CivNav images for unit {unit}. Available:")
            print_civnav_table(images)
            teardown(busid)
            sys.exit(1)
        images = filtered

    # Already sorted newest-first by find_civnav_images
    latest = images[0]
    log.info(f"Latest image: {latest['filename']}")
    log.info(f"  Date: {latest['date_formatted']}  SW: {latest['sw_version']}  HW: {latest['hw_version']}  Unit: {latest['unit']}")
    log.info(f"  Size: {latest['size_human']}")

    src_path = latest["path"]
    dst_path = os.path.join(dest_dir, latest["filename"])
    copy_file(src_path, dst_path)

    if not verify_copy(src_path, dst_path):
        log.error("INTEGRITY CHECK FAILED")
        teardown(busid)
        sys.exit(1)

    teardown(busid)
    log.info("=" * 60)
    log.info(f"SUCCESS: {latest['filename']} → {dst_path}")
    log.info("=" * 60)


def workflow_status() -> None:
    """Show current USB + mount status."""
    log.info("--- USBIPD Devices ---")
    devices = usbipd_list()
    for d in devices:
        log.info(f"  {d['busid']}  {d['description']}  [{d['state']}]")

    log.info("--- Mount Status ---")
    run_bash("status", check=False)


def teardown(busid: str) -> None:
    """Safe teardown: sync, unmount, detach."""
    log.info("--- Safe Teardown ---")
    run_bash("unmount", check=False)
    time.sleep(1)
    usbipd_detach(busid)
    log.info("Teardown complete — USB safe to remove")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="WSL USB Automation Agent — zero manual USB commands",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
CivNav image naming: civnav_{MMDDYYYY}_{SW}_{HW}_{UNIT}.img.gz
  Example: civnav_02232026_1.2.9_2.1.1_003.img.gz

Examples:
  # Deploy image from Windows Desktop to USB (your main use case)
  python3 usb_agent.py --to-usb "C:\Users\Civ Robotics\Desktop\civnav\civnav_02232026_1.2.9_2.1.1_003.img.gz" --usb-dest home/compulab

  # Same thing with WSL path
  python3 usb_agent.py --to-usb "/mnt/c/Users/Civ Robotics/Desktop/civnav/civnav_02232026_1.2.9_2.1.1_003.img.gz" --usb-dest home/compulab

  # Copy to USB root (no --usb-dest)
  python3 usb_agent.py --to-usb civnav_02232026_1.2.9_2.1.1_003.img.gz

  # Copy specific image FROM USB
  python3 usb_agent.py --from-usb civnav_02232026_1.2.9_2.1.1_003.img.gz

  # Auto-grab the latest CivNav image from USB
  python3 usb_agent.py --latest

  # List all CivNav images on USB
  python3 usb_agent.py --list-images

  # Check status
  python3 usb_agent.py --status
        """,
    )
    parser.add_argument("--from-usb", metavar="FILENAME", help="Copy specific file FROM USB to local")
    parser.add_argument("--to-usb", metavar="FILEPATH", help="Copy file TO USB (accepts Windows or WSL paths)")
    parser.add_argument("--usb-dest", metavar="PATH", default="", help="Destination dir ON the USB, relative to mount (e.g. home/compulab)")
    parser.add_argument("--dest", default=".", help="Destination directory for --from-usb/--latest (default: cwd)")
    parser.add_argument("--latest", action="store_true", help="Auto-detect and copy the latest CivNav image from USB")
    parser.add_argument("--unit", metavar="NUM", help="Filter by unit number (e.g. 003) — used with --latest")
    parser.add_argument("--list-images", action="store_true", help="List all CivNav images found on USB")
    parser.add_argument("--status", action="store_true", help="Show USB device and mount status")
    parser.add_argument("--mount-only", action="store_true", help="Only mount USB, don't copy")
    parser.add_argument("--unmount-only", action="store_true", help="Only unmount and detach USB")
    parser.add_argument("--skip-verify", action="store_true", help="Skip SHA256 verification (faster)")
    parser.add_argument("--busid", help="Manually specify USB bus ID (skip auto-detection)")

    args = parser.parse_args()

    # Dispatch
    if args.status:
        workflow_status()
    elif args.list_images:
        workflow_list_images(args.busid)
    elif args.latest:
        workflow_latest_from_usb(os.path.abspath(args.dest), args.unit)
    elif args.mount_only:
        devices = usbipd_list()
        usb_dev = find_usb_mass_storage(devices)
        if not usb_dev:
            sys.exit(1)
        busid = args.busid or usb_dev["busid"]
        if "attached" not in usb_dev["state"].lower():
            usbipd_attach(busid)
        run_bash("mount")
        log.info(f"USB mounted at {MOUNT_POINT} — run --unmount-only when done")
    elif args.unmount_only:
        devices = usbipd_list()
        usb_dev = find_usb_mass_storage(devices)
        if usb_dev:
            teardown(args.busid or usb_dev["busid"])
        else:
            run_bash("unmount", check=False)
    elif args.from_usb:
        workflow_from_usb(args.from_usb, os.path.abspath(args.dest), args.skip_verify)
    elif args.to_usb:
        workflow_to_usb(args.to_usb, args.usb_dest, args.skip_verify)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

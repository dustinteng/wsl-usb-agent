# WSL USB Automation Agent

Automated USB mount + copy toolchain for WSL2. Zero manual commands.

## Prerequisites

**Windows host:**
- [usbipd-win](https://github.com/dorssel/usbipd-win) installed (`winget install usbipd`)
- Run PowerShell/Terminal as Administrator

**WSL2:**
- Ubuntu (or similar) with `rsync` installed
- `sudo` access

## Image Naming Convention

```
civnav_{MMDDYYYY}_{SW_VER}_{HW_VER}_{UNIT}.img.gz
```

Example: `civnav_02232026_1.2.9_2.1.1_003.img.gz`

| Field | Example | Meaning |
|-------|---------|---------|
| Date | 02232026 | Feb 23, 2026 |
| SW | 1.2.9 | Software version |
| HW | 2.1.1 | Hardware version |
| Unit | 003 | Unit number |

## Quick Start

**Deploy image from Windows to USB (main use case):**
```bash
python3 usb_agent.py \
  --to-usb "C:\Users\Civ Robotics\Desktop\civnav\civnav_02232026_1.2.9_2.1.1_003.img.gz" \
  --usb-dest home/compulab
```

This will:
1. Auto-detect + attach USB via usbipd
2. Mount the ext4 partition to `/mnt/usb`
3. Copy the image to `/mnt/usb/home/compulab/civnav_02232026_1.2.9_2.1.1_003.img.gz`
4. Verify SHA256
5. Safely unmount + detach

**Other commands:**
```bash
# Copy FROM USB to local
python3 usb_agent.py --from-usb civnav_02232026_1.2.9_2.1.1_003.img.gz

# Auto-grab the latest CivNav image from USB
python3 usb_agent.py --latest

# List all CivNav images on USB
python3 usb_agent.py --list-images

# Check status
python3 usb_agent.py --status

# Mount only (browse manually)
python3 usb_agent.py --mount-only

# Safely unmount and detach
python3 usb_agent.py --unmount-only
```

**Windows paths are auto-converted:**
`C:\Users\Civ Robotics\...` becomes `/mnt/c/Users/Civ Robotics/...`

## What Happens

1. Detects USB via `usbipd list`
2. Binds + attaches device to WSL
3. Finds the ext4 partition (skips EFI/vfat)
4. Mounts to `/mnt/usb`
5. Copies with `rsync --progress --partial` (resumable)
6. Verifies SHA256 checksum
7. Syncs, unmounts, detaches

## Architecture

```
[ Windows PowerShell ]
        |
        | usbipd.exe (bind/attach/detach)
        v
[ WSL Ubuntu ]
        |
        | usb_agent.py  (Python orchestrator)
        | usb_mount.sh  (Bash mount/detect)
        v
[ rsync + SHA256 verify ]
```

## Files

| File | Role |
|------|------|
| `usb_agent.py` | Python orchestrator — CLI, usbipd, checksums, workflows |
| `usb_mount.sh` | Bash utility — device detection, partition selection, mount/unmount |
| `logs/` | Auto-generated log files per run |

## Bash Layer (usb_mount.sh)

Can also be used standalone:

```bash
sudo bash usb_mount.sh detect      # Find USB device
sudo bash usb_mount.sh mount       # Auto-detect + mount
sudo bash usb_mount.sh unmount     # Safe unmount
sudo bash usb_mount.sh list        # List files on USB
sudo bash usb_mount.sh status      # Check mount status
```

## Logs

Every run creates a timestamped log in `logs/`:
- `usb_agent_YYYYMMDD_HHMMSS.log`
- `usb_mount_YYYYMMDD_HHMMSS.log`

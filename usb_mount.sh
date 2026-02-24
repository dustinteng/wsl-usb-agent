#!/usr/bin/env bash
# =============================================================================
# usb_mount.sh — Layer 1: Bash USB utility for WSL2
# Handles: detect, mount, unmount, partition selection
# Must run inside WSL2 with sudo privileges
# =============================================================================
set -euo pipefail

MOUNT_POINT="/mnt/usb"
LOG_DIR="$(cd "$(dirname "$0")" && pwd)/logs"
LOG_FILE="${LOG_DIR}/usb_mount_$(date +%Y%m%d_%H%M%S).log"
MIN_DISK_SIZE_BYTES=$((1 * 1024 * 1024 * 1024))  # 1GB minimum

mkdir -p "$LOG_DIR"

# --- Logging ---
log() {
    local level="$1"; shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_error() { log "ERROR" "$@"; }

die() { log_error "$@"; exit 1; }

# --- Pre-flight checks ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run with sudo"
    fi
}

check_wsl() {
    if ! grep -qi microsoft /proc/version 2>/dev/null; then
        die "This script must be run inside WSL2"
    fi
}

# --- USB Detection ---
# Returns the device path of the detected USB removable disk
detect_usb_device() {
    log_info "Scanning for removable USB devices..."

    local devices=()
    while IFS= read -r line; do
        local name size rm type
        name=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        rm=$(echo "$line" | awk '{print $3}')
        type=$(echo "$line" | awk '{print $4}')

        # Filter: removable (RM=1), type=disk, size > minimum
        if [[ "$rm" == "1" && "$type" == "disk" ]]; then
            # Get size in bytes
            local size_bytes
            size_bytes=$(lsblk -bno SIZE "/dev/$name" 2>/dev/null | head -1)
            if [[ -n "$size_bytes" ]] && (( size_bytes > MIN_DISK_SIZE_BYTES )); then
                devices+=("$name|$size|$size_bytes")
                log_info "  Found: /dev/$name ($size, removable)"
            else
                log_info "  Skipping /dev/$name ($size) — too small"
            fi
        fi
    done < <(lsblk -dno NAME,SIZE,RM,TYPE 2>/dev/null)

    if [[ ${#devices[@]} -eq 0 ]]; then
        die "No removable USB devices detected (>1GB). Is the USB attached to WSL?"
    fi

    if [[ ${#devices[@]} -gt 1 ]]; then
        log_warn "Multiple USB devices found:"
        for d in "${devices[@]}"; do
            log_warn "  /dev/$(echo "$d" | cut -d'|' -f1) ($(echo "$d" | cut -d'|' -f2))"
        done
        # Pick the largest
        local best=""
        local best_size=0
        for d in "${devices[@]}"; do
            local s
            s=$(echo "$d" | cut -d'|' -f3)
            if (( s > best_size )); then
                best_size=$s
                best=$(echo "$d" | cut -d'|' -f1)
            fi
        done
        log_info "Auto-selecting largest: /dev/$best"
        echo "/dev/$best"
    else
        local dev_name
        dev_name=$(echo "${devices[0]}" | cut -d'|' -f1)
        log_info "Single USB device: /dev/$dev_name"
        echo "/dev/$dev_name"
    fi
}

# --- Partition Selection ---
# Given a disk device (e.g. /dev/sdd), find the best ext4 partition
select_partition() {
    local disk="$1"
    local disk_basename
    disk_basename=$(basename "$disk")

    log_info "Scanning partitions on $disk..."

    local best_part=""
    local best_size=0

    while IFS= read -r line; do
        local name fstype size_bytes
        name=$(echo "$line" | awk '{print $1}')
        fstype=$(echo "$line" | awk '{print $2}')
        size_bytes=$(echo "$line" | awk '{print $3}')

        # Skip the disk itself, only look at partitions
        [[ "$name" == "$disk_basename" ]] && continue

        # Must be a child of our disk
        if [[ "$name" != "${disk_basename}"* ]]; then
            continue
        fi

        log_info "  Partition: /dev/$name  fstype=$fstype  size=$size_bytes"

        # Prefer ext4; skip vfat/EFI partitions
        if [[ "$fstype" == "ext4" ]]; then
            if (( size_bytes > best_size )); then
                best_size=$size_bytes
                best_part="$name"
            fi
        fi
    done < <(lsblk -bnro NAME,FSTYPE,SIZE "$disk" 2>/dev/null)

    # Fallback: if no ext4 found, pick largest non-vfat partition
    if [[ -z "$best_part" ]]; then
        log_warn "No ext4 partition found. Trying largest non-vfat partition..."
        while IFS= read -r line; do
            local name fstype size_bytes
            name=$(echo "$line" | awk '{print $1}')
            fstype=$(echo "$line" | awk '{print $2}')
            size_bytes=$(echo "$line" | awk '{print $3}')

            [[ "$name" == "$disk_basename" ]] && continue
            [[ "$name" != "${disk_basename}"* ]] && continue
            [[ "$fstype" == "vfat" ]] && continue
            [[ -z "$fstype" ]] && continue

            if (( size_bytes > best_size )); then
                best_size=$size_bytes
                best_part="$name"
            fi
        done < <(lsblk -bnro NAME,FSTYPE,SIZE "$disk" 2>/dev/null)
    fi

    if [[ -z "$best_part" ]]; then
        die "No suitable partition found on $disk"
    fi

    log_info "Selected partition: /dev/$best_part"
    echo "/dev/$best_part"
}

# --- Mount ---
do_mount() {
    local partition="$1"

    # Check if already mounted
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        local current_dev
        current_dev=$(findmnt -n -o SOURCE "$MOUNT_POINT" 2>/dev/null || true)
        if [[ "$current_dev" == "$partition" ]]; then
            log_info "$MOUNT_POINT already mounted with $partition — skipping"
            return 0
        else
            log_warn "$MOUNT_POINT is mounted with $current_dev — unmounting first"
            umount "$MOUNT_POINT" || die "Failed to unmount existing $MOUNT_POINT"
        fi
    fi

    mkdir -p "$MOUNT_POINT"

    log_info "Mounting $partition → $MOUNT_POINT"
    if ! mount "$partition" "$MOUNT_POINT"; then
        die "Failed to mount $partition"
    fi

    log_info "Mount successful"
    # Show contents summary
    local file_count
    file_count=$(find "$MOUNT_POINT" -maxdepth 1 -type f 2>/dev/null | wc -l)
    log_info "Files at mount root: $file_count"
    ls -lh "$MOUNT_POINT" 2>/dev/null | head -20 | while read -r f; do
        log_info "  $f"
    done
}

# --- Unmount ---
do_unmount() {
    if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        log_info "$MOUNT_POINT is not mounted — nothing to do"
        return 0
    fi

    log_info "Syncing filesystem..."
    sync

    log_info "Unmounting $MOUNT_POINT..."
    if ! umount "$MOUNT_POINT"; then
        log_warn "Normal unmount failed, trying lazy unmount..."
        umount -l "$MOUNT_POINT" || die "Failed to unmount $MOUNT_POINT"
    fi

    log_info "Unmount successful"
}

# --- List USB contents ---
list_contents() {
    if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        die "$MOUNT_POINT is not mounted"
    fi

    log_info "Contents of $MOUNT_POINT:"
    find "$MOUNT_POINT" -maxdepth 2 -type f -printf '%s %p\n' 2>/dev/null | \
        sort -rn | head -50 | while read -r size path; do
        local human
        human=$(numfmt --to=iec "$size" 2>/dev/null || echo "${size}B")
        log_info "  $human  $path"
    done
}

# --- Main dispatch ---
usage() {
    cat <<EOF
Usage: sudo $0 <command> [options]

Commands:
  detect          Detect USB device and print device path
  partition DISK  Select best partition on DISK (e.g. /dev/sdd)
  mount           Auto-detect USB, select partition, mount to $MOUNT_POINT
  unmount         Safely unmount $MOUNT_POINT
  list            List files on mounted USB
  status          Show current mount status

Options:
  --mount-point PATH   Override mount point (default: $MOUNT_POINT)
EOF
}

# Parse global options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mount-point)
            MOUNT_POINT="$2"; shift 2 ;;
        -*)
            # Unknown option — break to let command parsing handle it
            break ;;
        *)
            break ;;
    esac
done

COMMAND="${1:-}"
shift || true

case "$COMMAND" in
    detect)
        check_root
        check_wsl
        detect_usb_device
        ;;
    partition)
        check_root
        check_wsl
        disk="${1:-}"
        [[ -z "$disk" ]] && die "Usage: $0 partition /dev/sdX"
        select_partition "$disk"
        ;;
    mount)
        check_root
        check_wsl
        disk=$(detect_usb_device)
        part=$(select_partition "$disk")
        do_mount "$part"
        ;;
    unmount|umount)
        check_root
        do_unmount
        ;;
    list|ls)
        list_contents
        ;;
    status)
        if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
            dev=$(findmnt -n -o SOURCE "$MOUNT_POINT" 2>/dev/null || echo "unknown")
            echo "MOUNTED: $MOUNT_POINT (device: $dev)"
        else
            echo "NOT_MOUNTED"
        fi
        ;;
    *)
        usage
        exit 1
        ;;
esac

#!/bin/bash
set -e

# Script configuration
WOLFSSL_REPO_PATH="__repo__/modules/crypto/wolfssl"
WOLFTPM_REPO_PATH="__repo__/modules/lib/wolftpm"

# Detect operating system
OS_TYPE="$(uname -s)"

# Display help information
show_help() {
    cat << EOF
SD Card Setup Script for wolfTPM/wolfSSL (macOS and Linux)

USAGE:
    ./setup_sdcard.sh [OPTIONS]

OPTIONS:
    -h, --help     Display this help message

DESCRIPTION:
    This script prepares an SD card by:
    1. Formatting it as FAT32 (if needed and confirmed)
    2. Copying certificate files from wolfSSL and wolfTPM repositories

INSTRUCTIONS:
    1. Insert your SD card
    2. Run this script
    3. Select the correct partition/disk identifier

macOS EXAMPLE:
    If your SD card shows as disk2:
    Enter: disk2 (the script will format the entire disk)

Linux EXAMPLE:
    If your SD card shows as /dev/sda with partition /dev/sda1:
    Enter: /dev/sda1 (you must specify a partition)

IMPORTANT:
    - macOS: Use disk identifiers like "disk2" (without /dev/)
    - Linux: Use partition paths like "/dev/sdb1" (not whole disk /dev/sdb)
    - This is a safety feature to prevent accidentally formatting your system drive

EOF
}

# Process command line arguments
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

echo "====================================================================="
echo "SD Card Setup Script for wolfTPM/wolfSSL (macOS/Linux)"
echo "====================================================================="
echo "Operating System Detected: $OS_TYPE"
echo ""

if [ "$OS_TYPE" = "Darwin" ]; then
    echo "Running on macOS - using 'diskutil' for disk operations"
    echo "Quick tip: Use 'diskutil list' to see all disks"
elif [ "$OS_TYPE" = "Linux" ]; then
    echo "Running on Linux - using standard mount tools"
    echo "Quick tip: Use 'lsblk' or 'fdisk -l' to see all disks"
else
    echo "Warning: Unsupported operating system: $OS_TYPE"
    echo "This script supports macOS (Darwin) and Linux only"
    exit 1
fi

echo ""
echo "This script will prepare an SD card with certificates from"
echo "wolfSSL and wolfTPM repositories"
echo ""
echo "For detailed instructions, run: ./setup_sdcard.sh --help"
echo "====================================================================="
echo ""

# First check that __repo__ exists
if [ ! -d "__repo__" ]; then
    echo "Error: __repo__ directory not found"
    echo "Please run this script after compiling the project"
    exit 1
fi

# Check that wolfssl and wolftpm repos are present
if [ ! -d "$WOLFSSL_REPO_PATH" ]; then
    echo "Error: wolfssl repo not found at $WOLFSSL_REPO_PATH"
    echo "Please run this script after compiling the project"
    exit 1
fi

if [ ! -d "$WOLFTPM_REPO_PATH" ]; then
    echo "Error: wolftpm repo not found at $WOLFTPM_REPO_PATH"
    echo "Please run this script after compiling the project"
    exit 1
fi

# Check for certs directories
if [ ! -d "$WOLFSSL_REPO_PATH/certs" ]; then
    echo "Error: wolfssl certs directory not found"
    exit 1
fi

if [ ! -d "$WOLFTPM_REPO_PATH/certs" ]; then
    echo "Error: wolftpm certs directory not found"
    exit 1
fi

# Function to display available disks (OS-specific)
list_disks() {
    if [ "$OS_TYPE" = "Darwin" ]; then
        # macOS
        echo "Available disks (macOS):"
        diskutil list
        echo ""
        echo "Look for 'external, physical' disks - these are typically SD cards or USB drives"
        echo "Common identifiers: disk2, disk3, disk4 (disk0 and disk1 are usually internal)"
    else
        # Linux
        echo "Available disk devices and partitions:"
        lsblk -o NAME,SIZE,TYPE,MODEL,MOUNTPOINT
        echo ""
        echo "Look for removable media (likely your SD card) based on size and model name."
    fi
}

# Function to get user input for SD card device (OS-specific)
get_sd_card_device() {
    list_disks
    echo ""
    
    if [ "$OS_TYPE" = "Darwin" ]; then
        echo "IMPORTANT: Enter the disk identifier WITHOUT /dev/ prefix (e.g., disk2)"
        echo "Do NOT use disk0 or disk1 as these are typically your system drives!"
        read -p "Enter the SD card disk identifier (e.g., disk2): " DISK_INPUT
        
        # Validate macOS disk identifier
        if [[ ! "$DISK_INPUT" =~ ^disk[0-9]+$ ]]; then
            echo "Error: Invalid disk identifier. Use format 'diskN' (e.g., disk2)"
            exit 1
        fi
        
        # Safety check - prevent using disk0 and disk1
        if [[ "$DISK_INPUT" =~ ^disk[01]$ ]]; then
            echo "Error: disk0 and disk1 are typically system drives. Refusing to proceed."
            echo "Your SD card is likely disk2 or higher."
            exit 1
        fi
        
        SD_CARD_DEVICE="/dev/$DISK_INPUT"
    else
        # Linux
        echo "IMPORTANT: You must specify a PARTITION (e.g., /dev/sdb1), not the whole disk!"
        read -p "Enter the SD card partition device (e.g., /dev/sdb1): " SD_CARD_DEVICE
        
        # Safety check - don't allow whole disk devices without partition numbers
        if [[ "$SD_CARD_DEVICE" =~ ^/dev/[a-z]+$ ]]; then
            echo "Error: You must specify a partition (e.g. /dev/sdb1), not a whole disk device"
            echo "This is for your safety to prevent accidentally wiping your system drive"
            exit 1
        fi
    fi
}

get_sd_card_device

# Check if the SD card device is valid
if [ ! -e "$SD_CARD_DEVICE" ]; then
    echo "Error: $SD_CARD_DEVICE does not exist"
    exit 1
fi

# Function to unmount device (OS-specific)
unmount_device() {
    if [ "$OS_TYPE" = "Darwin" ]; then
        echo "Unmounting all partitions on $SD_CARD_DEVICE..."
        diskutil unmountDisk "$SD_CARD_DEVICE" 2>/dev/null || true
    else
        if mount | grep -q "$SD_CARD_DEVICE "; then
            echo "Unmounting $SD_CARD_DEVICE..."
            sudo umount "$SD_CARD_DEVICE" || { echo "Failed to unmount device. Please unmount it manually."; exit 1; }
        fi
    fi
}

# Unmount if mounted
unmount_device

# Function to check and format filesystem (OS-specific)
check_and_format() {
    echo "Checking filesystem on $SD_CARD_DEVICE..."
    
    if [ "$OS_TYPE" = "Darwin" ]; then
        # macOS - check if already FAT32
        DISK_INFO=$(diskutil info "$SD_CARD_DEVICE" 2>/dev/null || echo "")
        if echo "$DISK_INFO" | grep -qi "FAT32\|MS-DOS FAT32"; then
            echo "Device is already FAT32 formatted."
            read -p "Do you want to reformat it? (y/n): " REFORMAT
            if [ "$REFORMAT" != "y" ]; then
                return 0
            fi
        fi
        
        echo "This will ERASE ALL DATA on $SD_CARD_DEVICE"
        read -p "Are you sure you want to format $SD_CARD_DEVICE as FAT32? (y/n): " FORMAT_CONFIRM
        if [ "$FORMAT_CONFIRM" = "y" ]; then
            echo "Formatting $SD_CARD_DEVICE as FAT32..."
            # Extract disk identifier without /dev/ for diskutil
            DISK_ID=$(basename "$SD_CARD_DEVICE")
            diskutil eraseDisk FAT32 WOLFCERTS MBR "$DISK_ID" || { echo "Formatting failed"; exit 1; }
        else
            echo "Aborting: Device must be FAT32 formatted"
            exit 1
        fi
    else
        # Linux
        if ! sudo blkid "$SD_CARD_DEVICE" | grep -qi "fat32\|vfat"; then
            echo "SD card device is not FAT32 formatted."
            read -p "Do you want to format it to FAT32? (y/n): " FORMAT_SD_CARD
            if [ "$FORMAT_SD_CARD" = "y" ]; then
                echo "Formatting $SD_CARD_DEVICE as FAT32..."
                sudo mkfs.fat -F 32 "$SD_CARD_DEVICE" || { echo "Formatting failed"; exit 1; }
            else
                echo "Aborting: SD card device must be FAT32 formatted"
                exit 1
            fi
        fi
    fi
}

check_and_format

# Function to mount device and copy files (OS-specific)
mount_and_copy() {
    if [ "$OS_TYPE" = "Darwin" ]; then
        # macOS - disk should auto-mount after format, or we can mount it
        echo ""
        echo "====================================================================="
        echo "macOS: Waiting for disk to mount..."
        echo "====================================================================="
        sleep 2
        
        # Determine the partition device (disk4 -> disk4s1)
        DISK_ID=$(basename "$SD_CARD_DEVICE")
        PARTITION_DEVICE="${SD_CARD_DEVICE}s1"
        
        # Find the mount point - check the partition first
        MOUNT_POINT=$(diskutil info "$PARTITION_DEVICE" 2>/dev/null | grep "Mount Point:" | cut -d: -f2- | xargs)
        
        if [ -z "$MOUNT_POINT" ] || [ "$MOUNT_POINT" = "Not applicable (no file system)" ]; then
            echo "Disk not mounted, attempting to mount..."
            diskutil mount "${DISK_ID}s1" 2>/dev/null || diskutil mount "$DISK_ID" || {
                echo "Error: Failed to mount device"
                exit 1
            }
            sleep 1
            # Check partition again after mounting
            MOUNT_POINT=$(diskutil info "$PARTITION_DEVICE" 2>/dev/null | grep "Mount Point:" | cut -d: -f2- | xargs)
            
            # If still empty, try checking the base disk
            if [ -z "$MOUNT_POINT" ]; then
                MOUNT_POINT=$(diskutil info "$SD_CARD_DEVICE" | grep "Mount Point:" | cut -d: -f2- | xargs)
            fi
        fi
        
        if [ -z "$MOUNT_POINT" ] || [ "$MOUNT_POINT" = "Not applicable (no file system)" ]; then
            echo "Error: Could not determine mount point"
            echo "Debug: Checking diskutil info..."
            diskutil info "$PARTITION_DEVICE"
            exit 1
        fi
        
        echo "Mounted at: $MOUNT_POINT"
        echo ""
        echo "====================================================================="
        echo "macOS: Copying certificates to SD card..."
        echo "====================================================================="
        
        # Copy files (no sudo needed on macOS for mounted volumes)
        mkdir -p "$MOUNT_POINT/certs-wolfssl" "$MOUNT_POINT/certs-wolftpm" || {
            echo "Error: Failed to create directories on SD card"
            diskutil unmount "$MOUNT_POINT"
            exit 1
        }
        
        cp -r "$WOLFSSL_REPO_PATH/certs/"* "$MOUNT_POINT/certs-wolfssl/" || {
            echo "Error: Failed to copy wolfssl certs"
            diskutil unmount "$MOUNT_POINT"
            exit 1
        }
        
        cp -r "$WOLFTPM_REPO_PATH/certs/"* "$MOUNT_POINT/certs-wolftpm/" || {
            echo "Error: Failed to copy wolftpm certs"
            diskutil unmount "$MOUNT_POINT"
            exit 1
        }
        
        echo "Syncing files to disk..."
        sync
        
        echo ""
        echo "====================================================================="
        echo "macOS: Ejecting SD card..."
        echo "====================================================================="
        diskutil eject "$SD_CARD_DEVICE" || {
            echo "Warning: Failed to eject device properly"
            diskutil unmount "$MOUNT_POINT"
        }
        
    else
        # Linux
        echo ""
        echo "====================================================================="
        echo "Linux: Mounting SD card..."
        echo "====================================================================="
        
        MOUNT_POINT="/tmp/sdcard-$(basename "$SD_CARD_DEVICE")-$$"
        sudo mkdir -p "$MOUNT_POINT"
        
        if [ ! -d "$MOUNT_POINT" ]; then
            echo "Error: Failed to create mount point directory"
            exit 1
        fi
        
        sudo mount "$SD_CARD_DEVICE" "$MOUNT_POINT" || {
            echo "Error: Failed to mount device"
            sudo rmdir "$MOUNT_POINT"
            exit 1
        }
        
        if ! mount | grep -q "$SD_CARD_DEVICE"; then
            echo "Error: Mount verification failed"
            sudo rmdir "$MOUNT_POINT"
            exit 1
        fi
        
        echo "Mounted at: $MOUNT_POINT"
        echo ""
        echo "====================================================================="
        echo "Linux: Copying certificates to SD card..."
        echo "====================================================================="
        
        sudo mkdir -p "$MOUNT_POINT/certs-wolfssl" "$MOUNT_POINT/certs-wolftpm"
        
        sudo cp -r "$WOLFSSL_REPO_PATH/certs/"* "$MOUNT_POINT/certs-wolfssl/" || {
            echo "Error: Failed to copy wolfssl certs"
            sudo umount "$MOUNT_POINT"
            sudo rmdir "$MOUNT_POINT"
            exit 1
        }
        
        sudo cp -r "$WOLFTPM_REPO_PATH/certs/"* "$MOUNT_POINT/certs-wolftpm/" || {
            echo "Error: Failed to copy wolftpm certs"
            sudo umount "$MOUNT_POINT"
            sudo rmdir "$MOUNT_POINT"
            exit 1
        }
        
        echo "Syncing files to disk..."
        sudo sync
        
        echo ""
        echo "====================================================================="
        echo "Linux: Unmounting SD card..."
        echo "====================================================================="
        sudo umount "$MOUNT_POINT" || echo "Warning: Failed to unmount $MOUNT_POINT"
        sudo rmdir "$MOUNT_POINT" || echo "Warning: Failed to remove mount point directory"
    fi
}

mount_and_copy

echo ""
echo "====================================================================="
echo "✓ SD card setup completed successfully!"
echo "====================================================================="
echo ""
echo "The following has been copied to your SD card:"
echo "  • wolfSSL certificates in: /certs-wolfssl/"
echo "  • wolfTPM certificates in: /certs-wolftpm/"
echo ""

if [ "$OS_TYPE" = "Darwin" ]; then
    echo "macOS Instructions:"
    echo "-------------------"
    echo "1. Your SD card has been ejected safely"
    echo "2. Remove the SD card from your Mac"
    echo "3. Insert it into your FRDM-MCXN947 board's SD card slot"
    echo "4. Power on the board and the certificates will be available"
    echo ""
    echo "Tip: If you need to re-insert the SD card into your Mac,"
    echo "     it will auto-mount to /Volumes/WOLFCERTS/"
else
    echo "Linux Instructions:"
    echo "-------------------"
    echo "1. Your SD card has been unmounted safely"
    echo "2. Remove the SD card from your computer"
    echo "3. Insert it into your FRDM-MCXN947 board's SD card slot"
    echo "4. Power on the board and the certificates will be available"
    echo ""
    echo "Tip: If you need to check the contents, re-insert the SD card"
    echo "     and it should auto-mount, or use: sudo mount /dev/sdXY /mnt"
fi

echo "====================================================================="
exit 0

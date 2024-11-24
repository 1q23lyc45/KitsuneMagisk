#!/sbin/sh
# ADDOND_VERSION=2
########################################################
#
# Magisk Survival Script for ROMs with addon.d support
# by topjohnwu and osm0sis
#
########################################################

SYSTEMINSTALL=false

# Detect whether in boot mode
[ -z $BOOTMODE ] && ps | grep zygote | grep -qv grep && BOOTMODE=true
[ -z $BOOTMODE ] && ps -A 2>/dev/null | grep zygote | grep -qv grep && BOOTMODE=true
[ -z $BOOTMODE ] && BOOTMODE=false

MAGISKBIN=/data/adb/magisk
MAGISKTMPDIR=/tmp/magisk
[ -z "$S" ] && S=/system
ADDOND="$S/addon.d"
APK="$S/addon.d/magisk/magisk.apk"

V1_FUNCS=/tmp/backuptool.functions
V2_FUNCS=/postinstall/tmp/backuptool.functions

if [ -f $V1_FUNCS ]; then
  . $V1_FUNCS
  backuptool_ab=false
elif [ -f $V2_FUNCS ]; then
  . $V2_FUNCS
else
  return 1
fi

ui_print() {
  if $BOOTMODE; then
    echo "$1"
  else
    echo -e "ui_print $1\nui_print" >> /proc/self/fd/$OUTFD
  fi
}

initialize() {
  mount /data 2>/dev/null
  local DATA=false
  local DATA_DE=false
  if grep ' /data ' /proc/mounts | grep -vq 'tmpfs'; then
    # Test if data is writable
    touch /data/.rw && rm /data/.rw && DATA=true
    # Test if data is decrypted
    $DATA && [ -d /data/adb ] && touch /data/adb/.rw && rm /data/adb/.rw && DATA_DE=true
    $DATA_DE && [ -d /data/adb/magisk ] || mkdir /data/adb/magisk || DATA_DE=false
  fi
  if [ -d "$MAGISKTMPDIR" ]; then
    MAGISKBIN="$MAGISKTMPDIR"
  elif [ ! -d "$MAGISKBIN" ]; then
    ui_print "***********************"
    ui_print " Magisk addon.d failed"
    ui_print "***********************"
    ui_print "! Cannot find Magisk binaries - was data wiped or not decrypted?"
    ui_print "! Reflash OTA from decrypted recovery or reflash Magisk"
    exit 1
  fi
  # Load utility functions
  . $MAGISKBIN/util_functions.sh

  if $BOOTMODE; then
    # Override ui_print when booted
    ui_print() { log -t Magisk -- "$1"; }
  fi
  OUTFD=
  setup_flashable
}

main() {
  if ! $backuptool_ab; then
    # Restore PREINITDEVICE from previous A-only partition
    if [ -f config.orig ]; then
      PREINITDEVICE=$(grep_prop PREINITDEVICE config.orig)
      rm config.orig
    fi

    # Wait for post addon.d-v1 processes to finish
    sleep 5
  fi

  # Ensure we aren't in /tmp/addon.d anymore (since it's been deleted by addon.d)
  mkdir -p $TMPDIR
  cd $TMPDIR

  if echo $MAGISK_VER | grep -q '\.'; then
    PRETTY_VER=$MAGISK_VER
  else
    PRETTY_VER="$MAGISK_VER($MAGISK_VER_CODE)"
  fi
  print_title "Magisk $PRETTY_VER addon.d"

  mount_partitions
  get_flags

  if $backuptool_ab; then
    # Restore PREINITDEVICE from previous A-only partition
    if [ -f config.orig ]; then
      PREINITDEVICE=$(grep_prop PREINITDEVICE config.orig)
      rm config.orig
    fi
    # Swap the slot for addon.d-v2
    if [ ! -z $SLOT ]; then
      case $SLOT in
        _a) SLOT=_b;;
        _b) SLOT=_a;;
      esac
    fi
  fi

  find_boot_image
  [ -z $BOOTIMAGE ] && abort "! Unable to detect target image"
  ui_print "- Target image: $BOOTIMAGE"

  api_level_arch_detect
  ui_print "- Device platform: $ABI"

  remove_system_su
  chmod -R 755 $MAGISKBIN
  if [ "$SYSTEMINSTALL" == "true" ];then
    unzip -oj "$ADDOND/magisk/magisk.apk" "res/raw/manager.sh"
    BOOTMODE_OLD="$BOOTMODE"
    . ./manager.sh
    BOOTMODE="$BOOTMODE_OLD"
    . $MAGISKBIN/util_functions.sh
    if $BOOTMODE; then
      direct_install_system "$MAGISKBINTMP" || { cleanup_system_installation; unmount_system_mirrors; abort "! Installation failed"; }
    else
      direct_install_system "$MAGISKBINTMP" || { cleanup_system_installation; abort "! Installation failed"; }
    fi
  else
    install_magisk
  fi

  # Cleanups
  cd /
  $BOOTMODE || recovery_cleanup
  rm -rf $TMPDIR

  ui_print "- Done"
  exit 0
}

case "$1" in
  backup)
    rm -rf "$MAGISKTMPDIR"
    if [ -d "$ADDOND/magisk" ] || [ -d "$S/etc/init/magisk" ]; then
      mkdir -p "$MAGISKTMPDIR"
      cp -af "$ADDOND/magisk/"* "$MAGISKTMPDIR"
      cp -af "$S/etc/init/magisk/"* "$MAGISKTMPDIR"
      mv "$MAGISKTMPDIR/boot_patch.sh.in" "$MAGISKTMPDIR/boot_patch.sh"
    fi
  ;;
  restore)
    # Stub
  ;;
  pre-backup)
    # Back up PREINITDEVICE from existing partition before OTA on A-only devices
    if ! $backuptool_ab; then
      initialize
      RECOVERYMODE=false
      find_boot_image
      $MAGISKBIN/magiskboot unpack "$BOOTIMAGE"
      $MAGISKBIN/magiskboot cpio ramdisk.cpio "extract .backup/.magisk config.orig"
      $MAGISKBIN/magiskboot cleanup
    fi
  ;;
  post-backup)
    # Stub
  ;;
  pre-restore)
    # Stub
  ;;
  post-restore)
    initialize
    if $backuptool_ab; then
      su=sh
      $BOOTMODE && su=su
      exec $su -c "sh $0 addond-v2"
    else
      # Run in background, hack for addon.d-v1
      (main) &
    fi
  ;;
  addond-v2)
    initialize
    main
  ;;
esac
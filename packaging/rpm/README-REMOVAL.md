# OpenWatch Complete Removal Guide

This document explains how to completely remove OpenWatch from your system.

## Important Note

**The `dnf remove openwatch` command only removes the RPM package but preserves all application data for safety.** This includes:

- Container images and volumes
- Application data (/var/lib/openwatch)
- Configuration files (/etc/openwatch)
- Log files (/var/log/openwatch)
- Generated keys and certificates
- Container networks and volumes

## Complete Removal Options

### Option 1: Basic Complete Cleanup
```bash
sudo /usr/share/openwatch/scripts/cleanup-openwatch.sh
```

This will:
- Stop all OpenWatch services
- Remove all containers, images, volumes, and networks
- Delete all application data and configuration files
- Remove user accounts and system integration
- Clean up SELinux policies and fapolicyd rules

### Option 2: Cleanup with Backup (Recommended)
```bash
sudo /usr/share/openwatch/scripts/cleanup-openwatch.sh --backup
```

This will:
- Create a compressed backup of important data before cleanup
- Perform complete removal as above
- Backup location: `/tmp/openwatch-backup-YYYYMMDD_HHMMSS.tar.gz`

### Option 3: Preview Cleanup Actions
```bash
sudo /usr/share/openwatch/scripts/cleanup-openwatch.sh --dry-run
```

This will show what would be cleaned up without making any changes.

### Option 4: Silent Cleanup (No Prompts)
```bash
sudo /usr/share/openwatch/scripts/cleanup-openwatch.sh --backup --force
```

This will perform cleanup with backup without asking for confirmation.

## What Gets Backed Up

When using `--backup`, the following data is preserved:

- **Configuration Files**: `/etc/openwatch/` (including secrets and keys)
- **Application Data**: `/var/lib/openwatch/` (scan results, database data)
- **Recent Logs**: Last 7 days from `/var/log/openwatch/`
- **Backup Manifest**: Instructions for restoration

## Restoring from Backup

If you need to restore OpenWatch after cleanup:

1. **Reinstall OpenWatch**:
   ```bash
   sudo dnf install openwatch-1.2.1-5.x86_64.rpm
   ```

2. **Stop Services**:
   ```bash
   sudo systemctl stop openwatch
   ```

3. **Extract and Restore Backup**:
   ```bash
   tar -xzf /tmp/openwatch-backup-YYYYMMDD_HHMMSS.tar.gz
   sudo cp -r openwatch-backup-*/config/* /etc/openwatch/
   sudo cp -r openwatch-backup-*/data/* /var/lib/openwatch/
   ```

4. **Fix Permissions**:
   ```bash
   sudo chown -R openwatch:openwatch /var/lib/openwatch
   sudo chown -R openwatch:openwatch /etc/openwatch
   ```

5. **Start Services**:
   ```bash
   sudo systemctl start openwatch
   ```

## Cleanup Script Options

| Option | Description |
|--------|-------------|
| `--backup` | Create backup before cleanup |
| `--force` | No confirmation prompts |
| `--dry-run` | Preview actions without making changes |
| `--verbose` | Show detailed output |
| `--help` | Show help message |

## What Remains After Standard RPM Removal

After `dnf remove openwatch`, these items remain on your system:

### Directories:
- `/etc/openwatch/` - Configuration and secrets
- `/var/lib/openwatch/` - Application data
- `/var/log/openwatch/` - Log files
- `/var/cache/openwatch/` - Cache data

### Container Runtime:
- OpenWatch container images
- Container volumes with database data
- Container networks
- Running containers (if not stopped)

### Generated Files:
- SSH keys in `/etc/openwatch/ssh/`
- JWT keypairs
- SSL certificates
- SCAP scan results

## Security Considerations

### Before Cleanup:
- Backup any important scan results or configuration
- Note any custom SCAP content that might need to be preserved
- Document any custom configuration changes

### After Cleanup:
- Verify no OpenWatch containers are running: `podman ps -a`
- Check for remaining OpenWatch images: `podman images`
- Confirm no OpenWatch processes: `ps aux | grep openwatch`

## Troubleshooting

### Permission Errors
If you encounter permission errors during cleanup:
```bash
sudo /usr/share/openwatch/scripts/cleanup-openwatch.sh --verbose
```

### Containers Won't Stop
If containers are stuck:
```bash
sudo podman kill $(podman ps -q --filter "label=project=openwatch")
sudo podman rm -f $(podman ps -aq --filter "label=project=openwatch")
```

### Partial Cleanup Recovery
If cleanup fails partway through, you can:
1. Run with `--dry-run` to see remaining items
2. Use `--force` to skip confirmations on retry
3. Manually remove specific components as needed

## Support

For issues with cleanup or removal:
1. Check the cleanup script help: `--help`
2. Use dry-run mode to diagnose: `--dry-run --verbose`
3. Review OpenWatch documentation
4. Contact support with backup manifest and error details

---

**Remember**: Complete cleanup is irreversible without backup. Always use `--backup` unless you're absolutely certain you don't need the data.

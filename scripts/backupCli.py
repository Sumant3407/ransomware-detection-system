"""Command-line utility for managing Ransomware Detection System backups and recovery."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from app.operations.backupManager import BackupManager


def parseArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ransomware Detection System Backup & Disaster Recovery CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m scripts.backupCli --create --description "Pre-upgrade snapshot"
  python -m scripts.backupCli --list
  python -m scripts.backupCli --list --json
  python -m scripts.backupCli --verify data/backups/backup_20261008_120000.zip
  python -m scripts.backupCli --restore data/backups/backup_20261008_120000.zip --force
  python -m scripts.backupCli --prune --keep 5
        """,
    )

    parser.add_argument("--create", action="store_true", help="Create a new system backup archive")
    parser.add_argument("--description", type=str, default="", help="Description for the backup manifest")
    parser.add_argument("--no-models", action="store_true", help="Exclude model artifacts from backup")
    parser.add_argument("--list", dest="listBackups", action="store_true", help="List all available backups")
    parser.add_argument("--verify", type=str, default=None, help="Path to backup ZIP to verify")
    parser.add_argument("--restore", type=str, default=None, help="Path to backup ZIP to restore")
    parser.add_argument("--force", action="store_true", help="Bypass confirmation prompt for restore")
    parser.add_argument("--prune", action="store_true", help="Prune older backups exceeding retention limit")
    parser.add_argument("--keep", type=int, default=10, help="Maximum number of backups to keep (default: 10)")
    parser.add_argument("--backup-dir", type=str, default=None, help="Custom backups directory")
    parser.add_argument("--json", dest="jsonOutput", action="store_true", help="Output results in JSON format")

    return parser.parse_args()


def main() -> int:
    args = parseArguments()
    manager = BackupManager(
        backupDirectory=args.backup_dir,
        maxRetainedBackups=args.keep,
    )

    # 1. Create Backup
    if args.create:
        result = manager.createBackup(
            description=args.description,
            includeModels=not args.no_models,
            autoPrune=True,
        )
        if args.jsonOutput:
            out = {
                "success": result.success,
                "backupId": result.backupId,
                "backupPath": str(result.backupPath) if result.backupPath else None,
                "manifest": result.manifest.toDict() if result.manifest else None,
                "error": result.errorMessage,
                "durationSeconds": result.durationSeconds,
            }
            print(json.dumps(out, indent=2))
        else:
            if result.success and result.manifest:
                print("==================================================")
                print("             BACKUP CREATED SUCCESSFULLY          ")
                print("==================================================")
                print(f"  Backup ID:        {result.backupId}")
                print(f"  Path:             {result.backupPath}")
                print(f"  Total Files:      {len(result.manifest.files)}")
                print(f"  Models Included:  {result.manifest.modelsCount}")
                print(f"  Total Size:       {result.manifest.totalSizeBytes / 1024:.1f} KB")
                print(f"  Duration:         {result.durationSeconds:.2f}s")
                if result.manifest.databaseStats:
                    print("  Database Tables:")
                    for tbl, cnt in result.manifest.databaseStats.items():
                        print(f"    - {tbl:<18}: {cnt} rows")
                print("==================================================")
            else:
                print(f"[ERROR] Backup creation failed: {result.errorMessage}", file=sys.stderr)
                return 1
        return 0

    # 2. List Backups
    if args.listBackups:
        backups = manager.listBackups()
        if args.jsonOutput:
            print(json.dumps(backups, indent=2))
        else:
            print("==================================================")
            print("               AVAILABLE SYSTEM BACKUPS           ")
            print("==================================================")
            if not backups:
                print("  No backups found in directory.")
            else:
                for idx, b in enumerate(backups, 1):
                    sizeKb = b["sizeBytes"] / 1024.0
                    print(f"  [{idx}] {b['backupId']}")
                    print(f"      Path:        {b['path']}")
                    print(f"      Created:     {b['createdAt']}")
                    print(f"      Size:        {sizeKb:.1f} KB (Models: {b['modelsCount']})")
                    if b["description"]:
                        print(f"      Description: {b['description']}")
                    print()
            print("==================================================")
        return 0

    # 3. Verify Backup
    if args.verify:
        isValid, message, manifest = manager.verifyBackup(args.verify)
        if args.jsonOutput:
            print(json.dumps({
                "valid": isValid,
                "message": message,
                "manifest": manifest.toDict() if manifest else None,
            }, indent=2))
        else:
            statusStr = "[OK] VERIFIED" if isValid else "[FAILED] CORRUPTED"
            print("==================================================")
            print(f"  BACKUP VERIFICATION: {statusStr}")
            print("==================================================")
            print(f"  Archive:     {args.verify}")
            print(f"  Result:      {message}")
            if manifest:
                print(f"  Backup ID:   {manifest.backupId}")
                print(f"  Files Count: {len(manifest.files)}")
                print(f"  Models:      {manifest.modelsCount}")
            print("==================================================")
        return 0 if isValid else 1

    # 4. Restore Backup
    if args.restore:
        zipPath = Path(args.restore)
        if not zipPath.is_file():
            print(f"[ERROR] Backup file not found: {zipPath}", file=sys.stderr)
            return 1

        if not args.force:
            print(f"WARNING: Restoring backup from '{zipPath}' will overwrite current database and active models.")
            confirm = input("Are you sure you want to proceed? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Restore aborted by user.")
                return 0

        result = manager.restoreBackup(zipPath, createSafetySnapshot=True)
        if args.jsonOutput:
            print(json.dumps({
                "success": result.success,
                "backupId": result.backupId,
                "restoredFiles": result.restoredFiles,
                "preRestoreBackup": str(result.preRestoreBackupPath) if result.preRestoreBackupPath else None,
                "error": result.errorMessage,
                "durationSeconds": result.durationSeconds,
            }, indent=2))
        else:
            if result.success:
                print("==================================================")
                print("            RESTORE COMPLETED SUCCESSFULLY        ")
                print("==================================================")
                print(f"  Restored ID:         {result.backupId}")
                print(f"  Restored Files:      {len(result.restoredFiles)}")
                for f in result.restoredFiles:
                    print(f"    - {f}")
                if result.preRestoreBackupPath:
                    print(f"  Safety Snapshot:     {result.preRestoreBackupPath}")
                print(f"  Duration:            {result.durationSeconds:.2f}s")
                print("==================================================")
            else:
                print(f"[ERROR] Restore failed: {result.errorMessage}", file=sys.stderr)
                return 1
        return 0

    # 5. Prune Backups
    if args.prune:
        deleted = manager.pruneBackups(maxRetained=args.keep)
        if args.jsonOutput:
            print(json.dumps({"prunedCount": len(deleted), "deleted": deleted}, indent=2))
        else:
            print(f"Pruned {len(deleted)} old backup(s) (retaining max {args.keep}).")
            for d in deleted:
                print(f"  Deleted: {d}")
        return 0

    # Default: show help
    print("No action specified. Use --help to view available options.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

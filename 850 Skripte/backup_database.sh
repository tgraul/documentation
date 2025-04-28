#!/bin/bash
# ======================================================================
# MySQL/MariaDB Datenbank-Backup Skript
# ======================================================================
# BESCHREIBUNG:
#   Erstellt ein Backup aller Datenbanken und sendet eine
#   E-Mail-Benachrichtigung.
#
# VERWENDUNG:
#   ./backup_database.sh [config-file]
#
# CONFIG-DATEI (Standard: backup_config.conf):
#   DB_USER="dbuser"
#   DB_PASSWORD="dbpassword"
#   DB_HOST="localhost"
#   BACKUP_DIR="/path/to/backups"
#   RETENTION_DAYS=14
#   EMAIL_TO="admin@example.com"
#
# ======================================================================

# Standardkonfigurationsdatei
CONFIG_FILE="backup_config.conf"

# Wenn Konfigurationsdatei als Parameter übergeben wurde
if [ $# -eq 1 ]; then
  CONFIG_FILE=$1
fi

# Prüfe, ob Konfigurationsdatei existiert
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Fehler: Konfigurationsdatei $CONFIG_FILE nicht gefunden!"
  exit 1
fi

# Lade Konfiguration
source "$CONFIG_FILE"

# Überprüfe erforderliche Variablen
if [ -z "$DB_USER" ] || [ -z "$BACKUP_DIR" ]; then
  echo "Fehler: Erforderliche Konfigurationsvariablen fehlen!"
  exit 1
fi

# Erstelle Backup-Verzeichnis, falls es nicht existiert
mkdir -p "$BACKUP_DIR"

# Setze Datum und Logdatei
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="$BACKUP_DIR/backup_$DATE.log"
BACKUP_FILE="$BACKUP_DIR/all_databases_$DATE.sql.gz"

# Starte Backup-Prozess
{
  echo "========== Datenbank-Backup gestartet: $(date) =========="
  echo "Backup-Datei: $BACKUP_FILE"
  
  # Führe mysqldump aus
  if [ -z "$DB_PASSWORD" ]; then
    # Ohne Passwort
    mysqldump --user="$DB_USER" --host="$DB_HOST" --all-databases --events --routines \
      --triggers --single-transaction --quick | gzip > "$BACKUP_FILE"
  else
    # Mit Passwort
    mysqldump --user="$DB_USER" --password="$DB_PASSWORD" --host="$DB_HOST" \
      --all-databases --events --routines --triggers --single-transaction --quick | gzip > "$BACKUP_FILE"
  fi
  
  # Prüfe, ob Backup erfolgreich war
  if [ $? -eq 0 ]; then
    # Setze Berechtigungen
    chmod 600 "$BACKUP_FILE"
    
    # Größe des Backups
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    
    echo "Backup erfolgreich erstellt. Größe: $BACKUP_SIZE"
    
    # Lösche alte Backups
    if [ ! -z "$RETENTION_DAYS" ]; then
      echo "Lösche Backups älter als $RETENTION_DAYS Tage..."
      find "$BACKUP_DIR" -name "all_databases_*.sql.gz" -type f -mtime +$RETENTION_DAYS -delete
      find "$BACKUP_DIR" -name "backup_*.log" -type f -mtime +$RETENTION_DAYS -delete
      echo "Alte Backups wurden gelöscht."
    fi
    
    # Sende E-Mail-Benachrichtigung, wenn konfiguriert
    if [ ! -z "$EMAIL_TO" ]; then
      echo "Sende E-Mail-Benachrichtigung an $EMAIL_TO..."
      echo "Datenbank-Backup erfolgreich erstellt am $(date)" | mail -s "Datenbank-Backup erfolgreich" "$EMAIL_TO"
      echo "E-Mail wurde gesendet."
    fi
    
    echo "========== Datenbank-Backup abgeschlossen: $(date) =========="
    exit 0
  else
    echo "FEHLER: Datenbank-Backup fehlgeschlagen!"
    
    # Sende Fehler-E-Mail, wenn konfiguriert
    if [ ! -z "$EMAIL_TO" ]; then
      echo "Sende Fehler-E-Mail-Benachrichtigung an $EMAIL_TO..."
      echo "Datenbank-Backup fehlgeschlagen am $(date). Bitte Log-Datei überprüfen." | mail -s "FEHLER: Datenbank-Backup fehlgeschlagen" "$EMAIL_TO"
      echo "Fehler-E-Mail wurde gesendet."
    fi
    
    echo "========== Datenbank-Backup fehlgeschlagen: $(date) =========="
    exit 1
  fi
} | tee -a "$LOG_FILE" 
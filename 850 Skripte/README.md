# 🧰 Skript-Bibliothek

Diese Skript-Bibliothek enthält nützliche Skripte für die Automatisierung von DevOps- und Systemadministrationsaufgaben.

## Verwendung

1. Skripte sind nach Verwendungszweck kategorisiert
2. Jedes Skript enthält Dokumentation in den Kommentaren
3. Skripte können kopiert, angepasst und in eigenen Workflows verwendet werden

## Verfügbare Skripte

### Backup & Wiederherstellung
- [backup_database.sh](backup_database.sh) - MySQL/MariaDB-Datenbank-Backup mit Rotation und E-Mail-Benachrichtigung

### Monitoring & Wartung
- monitoring_disk_space.sh - Überwachung von Festplattenplatz mit Warnungen
- cleanup_logs.sh - Bereinigung und Rotation von Logdateien

### Sicherheit
- security_audit.sh - Einfaches Sicherheitsaudit für Linux-Server
- ssl_cert_check.sh - Überprüfung der SSL-Zertifikatsgültigkeit

### Container & Orchestrierung
- docker_prune.sh - Bereinigung nicht verwendeter Docker-Ressourcen
- k8s_namespace_cleanup.sh - Kubernetes-Namespace-Bereinigung

## Beitragen

Um neue Skripte hinzuzufügen:

1. Erstelle ein neues Skript in der entsprechenden Kategorie
2. Stelle sicher, dass das Skript gut dokumentiert ist
3. Aktualisiere diese README mit Informationen zum neuen Skript

## Best Practices für Skripte

- Verwende eine klare Dokumentation im Skript-Header
- Implementiere Fehlerbehandlung
- Füge Logging hinzu
- Setze sinnvolle Exit-Codes
- Prüfe ausreichende Berechtigungen
- Vermeide hartcodierte Anmeldeinformationen

## Verwandte Dokumentation

- [[800 Tooling/801 Bash|Bash-Dokumentation]]
- [[800 Tooling/804 CLI-Tools|CLI-Tools]]
- [[400 CI_CD & Automation/000 CI_CD MOC|CI/CD & Automation]] 
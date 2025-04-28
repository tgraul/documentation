# Linux Basics

Tags: #linux #betriebssystem #concept

## Überblick
Linux ist ein Open-Source-Betriebssystem, das auf dem Linux-Kernel basiert. Es ist bekannt für seine Stabilität, Sicherheit und Flexibilität, insbesondere in Server- und Cloud-Umgebungen.

## Wichtige Linux-Distributionen

### Debian-basiert
- **Debian**: Stabile, freie Linux-Distribution
- **Ubuntu**: Benutzerfreundlich, große Community
- **Linux Mint**: Einsteigerfreundlich mit vertrautem Desktop

### Red Hat-basiert
- **RHEL**: Enterprise-Linux mit Support
- **CentOS/Rocky Linux/Alma Linux**: Freie Alternativen zu RHEL
- **Fedora**: Bleeding-edge, von Red Hat unterstützt

### Andere
- **Arch Linux**: Rolling-Release, minimalistisch
- **openSUSE**: Stabil und Enterprise-tauglich
- **Alpine**: Leichtgewichtig, für Container optimiert

## Grundlegende Befehle

### Dateisystem
```bash
ls -la            # Dateien auflisten (auch versteckte)
cd /pfad/zu/dir   # Verzeichnis wechseln
pwd               # Aktuelles Verzeichnis anzeigen
mkdir dirname     # Verzeichnis erstellen
rm datei          # Datei löschen
rm -rf verzeichnis # Verzeichnis rekursiv löschen (Vorsicht!)
cp quelle ziel    # Dateien kopieren
mv quelle ziel    # Dateien verschieben/umbenennen
```

### Systeminformationen
```bash
uname -a          # Kernel-Informationen
cat /etc/os-release # Betriebssysteminfos
df -h             # Festplattennutzung
free -h           # Speichernutzung
top / htop        # Prozesse anzeigen
```

### Paketverwaltung
#### Debian/Ubuntu
```bash
apt update        # Paketliste aktualisieren
apt upgrade       # Pakete aktualisieren
apt install paket # Paket installieren
apt remove paket  # Paket entfernen
```

#### RHEL/CentOS
```bash
dnf update        # Pakete aktualisieren
dnf install paket # Paket installieren
dnf remove paket  # Paket entfernen
```

## Dateibearbeitung
Gängige Texteditoren:
- **vim/vi**: Mächtiger Terminal-Editor
- **nano**: Einfacher Terminal-Editor
- **emacs**: Umfangreicher Editor/IDE

## Benutzer- und Rechteverwaltung
```bash
whoami            # Aktueller Benutzer
useradd username  # Benutzer anlegen
passwd username   # Passwort setzen
chmod 755 datei   # Rechte ändern
chown user:gruppe datei # Besitzer ändern
```

## Prozessverwaltung
```bash
ps aux            # Alle Prozesse anzeigen
kill PID          # Prozess beenden
systemctl status service # Dienststatus prüfen
systemctl start/stop/restart service # Dienst steuern
journalctl -u service # Logs für Dienst anzeigen
```

## Netzwerk
```bash
ip a              # Netzwerkschnittstellen anzeigen
ping host         # Host anpingen
netstat -tulpn    # Offene Ports anzeigen
ss -tulpn         # Alternative zu netstat
```

## Verwandte Themen
- [[211 Linux Firewall]]
- [[212 Linux Systemd]]
- [[213 Linux Dateisystem]]
- [[610 Linux-Härtung]] 
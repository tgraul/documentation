# fail2ban

Tags: #tool #security #intrusion-prevention

## Überblick
fail2ban ist ein Intrusion Prevention Framework, das Logdateien überwacht und IP-Adressen blockiert, von denen verdächtige Aktivitäten wie wiederholte Anmeldeversuche oder automatische Scans ausgehen. Es arbeitet mit iptables/firewalld, um Firewall-Regeln dynamisch zu erstellen.

## Installationsschritte
```bash
# Installation auf Debian/Ubuntu
sudo apt update
sudo apt install fail2ban

# Installation auf CentOS/RHEL
sudo dnf install epel-release
sudo dnf install fail2ban

# Dienst starten und aktivieren
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## Grundlegende Konfiguration
Die Hauptkonfigurationsdateien befinden sich in `/etc/fail2ban/`.

```ini
# /etc/fail2ban/jail.local - Konfigurationsbeispiel
[DEFAULT]
# "bantime" ist die Zeit in Sekunden, für die eine IP gesperrt wird
bantime = 3600
# "findtime" ist der Zeitraum in Sekunden, in dem "maxretry" erreicht werden muss, um gesperrt zu werden
findtime = 600
# "maxretry" ist die Anzahl der Versuche, bevor eine IP gesperrt wird
maxretry = 5
# Ignoriere bestimmte IPs (z.B. eigene Server)
ignoreip = 127.0.0.1/8 192.168.1.0/24

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
```

## Wichtige Befehle
```bash
# Status prüfen
sudo fail2ban-client status

# Status eines bestimmten Jails prüfen
sudo fail2ban-client status sshd

# Alle aktuellen Sperren anzeigen
sudo fail2ban-client banned

# IP für einen Jail entsperren
sudo fail2ban-client set sshd unbanip 10.0.0.1

# Konfiguration neu laden
sudo fail2ban-client reload

# Testen einer Regelkonfiguration
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
```

## Best Practices
- Erstelle eine eigene `jail.local` Datei statt die `jail.conf` zu ändern
- Passe `bantime`, `findtime` und `maxretry` an deine Bedürfnisse an
- Füge deine eigenen IP-Adressen zur `ignoreip` Liste hinzu
- Implementiere Email-Benachrichtigungen für wichtige Ereignisse
- Prüfe regelmäßig die Logs auf falsch-positive Sperren
- Behalte Filter aktuell, um neue Angriffsmuster zu erkennen

## Häufige Probleme und Lösungen
- **Keine Sperren**: Überprüfe Logpfade und Firewall-Konfiguration
- **Eigene IP gesperrt**: Füge deine IP zu `ignoreip` hinzu
- **Log-Format hat sich geändert**: Passe Filter-Regex entsprechend an
- **fail2ban startet nicht**: Prüfe die Konfiguration mit `fail2ban-client -d`

## Sicherheitshinweise
- fail2ban ist kein Ersatz für eine vollständige Firewall-Konfiguration
- Richtig konfigurierte Passwort-Policies und SSH-Schlüssel bieten zusätzlichen Schutz
- Der Dienst sollte mit minimalen Rechten laufen
- Zugriffsrechte für die Konfigurationsdateien einschränken
- Ein zu kurzes `bantime` könnte Brute-Force-Angriffe nicht effektiv verhindern

## Monitoring & Logging
- Logs befinden sich standardmäßig in `/var/log/fail2ban.log`
- Überwache die Häufigkeit der Sperrungen
- Regelmäßig die Logs auf ungewöhnliche Aktivitäten prüfen
- Integriere fail2ban-Logs in zentrale Logging-Systeme (z.B. ELK Stack)

## Nützliche Links
- [Offizielle fail2ban-Dokumentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [fail2ban auf GitHub](https://github.com/fail2ban/fail2ban)
- [Community-Filter-Collection](https://github.com/mitchellkrogza/Fail2Ban-Blacklist-JAIL-for-Repeat-Offenders-with-Perma-Extended-Banning)

## Verwandte Themen
- [[600 Security/661 PortSentry|PortSentry]]
- [[600 Security/662 psad|psad]]
- [[200 Betriebssysteme/211 Linux Firewall|Linux Firewall]]
- [[600 Security/610 Linux-Härtung|Linux-Härtung]] 
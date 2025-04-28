---
tags: [security, linux, hardening, checkliste]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
---

# Server Hardening Checkliste

> [!INFO]
> Diese Checkliste dient zur Absicherung neuer Linux-Server. Passe sie an deine spezifischen Anforderungen an.

## 📋 Initiale Einrichtung

- [ ] Root-Login via SSH deaktivieren
- [ ] SSH-Schlüssel statt Passwort-Authentifizierung einrichten
- [ ] SSH auf nicht-Standard-Port konfigurieren (optional)
- [ ] Sudo-Benutzer mit eingeschränkten Rechten erstellen
- [ ] Firewall einrichten (UFW/firewalld/iptables)
- [ ] Nur benötigte Ports öffnen
- [ ] fail2ban installieren und konfigurieren
- [ ] Automatische Updates für Sicherheitspatches aktivieren
- [ ] Nicht benötigte Pakete entfernen

## 🔐 Passwort-Richtlinien

- [ ] Starke Passwort-Richtlinien mit PAM konfigurieren
- [ ] Passwort-History aktivieren
- [ ] Passwort-Alterung einrichten
- [ ] `libpam-pwquality` installieren
- [ ] Passwörter für sudo-Aktionen erzwingen

## 🔍 Auditing & Logging

- [ ] Systemlogs auf zentralen Log-Server schicken
- [ ] Audit-Dienst (auditd) aktivieren
- [ ] Login-Versuche protokollieren
- [ ] sudo-Ausführungen protokollieren
- [ ] Log-Rotationsrichtlinien einrichten

## 🛡️ Systemhärtung

- [ ] AIDE für Integritätsprüfung installieren
- [ ] SUID/SGID-Binaries einschränken oder überwachen
- [ ] Nicht benötigte Dienste deaktivieren
- [ ] SSH-Konfiguration absichern (Cipher/MACs)
- [ ] /tmp und /var/tmp als separate Partitionen mit noexec-Option
- [ ] Kernel-Parameter in sysctl.conf härten:
  - [ ] IP-Spoofing-Schutz
  - [ ] TCP SYN-Cookies
  - [ ] ICMP-Redirects deaktivieren

## 🔎 Netzwerksicherheit

- [ ] Port-Scanning-Erkennung (psad) einrichten
- [ ] TCP-Wrapper für zusätzliche Zugriffskontrolle verwenden
- [ ] IPv6 deaktivieren, wenn nicht benötigt
- [ ] Netzwerkschnittstellen richtig konfigurieren
- [ ] DNS absichern (falls vorhanden)

## 🧾 Compliance & Dokumentation

- [ ] Basis-Konfiguration dokumentieren
- [ ] Installierte Software und Versionen dokumentieren
- [ ] Härtungsmaßnahmen dokumentieren
- [ ] Regelmäßige Überprüfungen planen

## 📈 Überwachung einrichten

- [ ] Resource-Monitoring (CPU, RAM, Disk)
- [ ] Service-Überwachung
- [ ] Benachrichtigungen bei kritischen Ereignissen
- [ ] Security-Scans regelmäßig durchführen

## 🧪 Tests

- [ ] Penetrationstests planen
- [ ] Firewall-Regeln testen
- [ ] SSH-Zugriff verifizieren
- [ ] Notfall-Wiederherstellung testen

## Verwandte Themen
- [[600 Security/610 Linux-Härtung|Linux-Härtung]]
- [[600 Security/660 fail2ban|fail2ban]]
- [[200 Betriebssysteme/211 Linux Firewall|Linux Firewall]] 
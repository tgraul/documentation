---
tags: [security, linux, hardening, checkliste]
erstelldatum: 2025-04-28
aktualisiert: <% tp.date.now("YYYY-MM-DD") %>
status: in_progress
---

# Server Hardening Checkliste

> [!info] Anleitung
> Diese Checkliste dient zur Absicherung neuer Linux-Server. Passe sie an deine spezifischen Anforderungen an.

> [!danger] Sicherheitshinweis
> Stelle sicher, dass du vor allen Änderungen ein Backup oder Snapshot des Systems erstellt hast und Zugriff für den Notfall sichergestellt ist.

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

## 📊 Fortschritt

```dataviewjs
// Zähle die erledigten Aufgaben dieser Checkliste
const page = dv.current();
const tasks = dv.current().file.tasks;
const completedTasks = tasks.where(t => t.completed);
const totalTasks = tasks.length;
const percentComplete = totalTasks > 0 ? Math.round((completedTasks.length / totalTasks) * 100) : 0;

dv.paragraph(`Fortschritt: ${completedTasks.length}/${totalTasks} (${percentComplete}%)`);

// Erstelle eine einfache Fortschrittsleiste
const progressBar = "🟩".repeat(Math.floor(percentComplete/10)) + "⬜".repeat(10 - Math.floor(percentComplete/10));
dv.paragraph(progressBar);
```

## ⚙️ Beispiel-Konfigurationen

> [!example] SSH-Konfiguration
> ```bash
> # /etc/ssh/sshd_config
> PermitRootLogin no
> PasswordAuthentication no
> PubkeyAuthentication yes
> PermitEmptyPasswords no
> X11Forwarding no
> MaxAuthTries 3
> ```

> [!example] Firewall-Konfiguration (UFW)
> ```bash
> # UFW-Grundkonfiguration
> ufw default deny incoming
> ufw default allow outgoing
> ufw allow 22/tcp comment 'SSH'
> ufw enable
> ```

## Verwandte Themen
- [[600 Security/610 Linux-Härtung|Linux-Härtung]]
- [[600 Security/660 fail2ban|fail2ban]]
- [[200 Betriebssysteme/211 Linux Firewall|Linux Firewall]]

---

Zuletzt aktualisiert: <% tp.date.now("YYYY-MM-DD") %> 
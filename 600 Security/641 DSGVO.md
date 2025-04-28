---
tags: [security, compliance, dsgvo, gdpr, datenschutz, ciso]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
---

# DSGVO / GDPR

> [!INFO]
> Die Datenschutz-Grundverordnung (DSGVO) ist eine EU-Verordnung zum Schutz personenbezogener Daten. Diese Dokumentation fokussiert sich auf die technischen Anforderungen für IT-Systeme.

## 📋 Grundlagen der DSGVO

Die DSGVO (Datenschutz-Grundverordnung) oder GDPR (General Data Protection Regulation) gilt seit dem 25. Mai 2018 in allen EU-Mitgliedstaaten und hat weitreichende Auswirkungen auf die Verarbeitung personenbezogener Daten.

### Schlüsselprinzipien

1. **Rechtmäßigkeit, Transparenz**: Personenbezogene Daten müssen auf rechtmäßige Weise, für betroffene Personen transparent verarbeitet werden
2. **Zweckbindung**: Daten dürfen nur für festgelegte, eindeutige und legitime Zwecke erhoben werden
3. **Datenminimierung**: Nur die Daten, die für den Zweck notwendig sind, dürfen erhoben werden
4. **Richtigkeit**: Personenbezogene Daten müssen korrekt und auf dem neuesten Stand sein
5. **Speicherbegrenzung**: Daten dürfen nur so lange gespeichert werden, wie es für den Zweck erforderlich ist
6. **Integrität und Vertraulichkeit**: Angemessene Sicherheit muss gewährleistet sein
7. **Rechenschaftspflicht**: Nachweis der Einhaltung aller Prinzipien

## 🔐 Technische und organisatorische Maßnahmen (TOMs)

Als DevOps Engineer oder Systemadministrator ist die Implementierung geeigneter technischer und organisatorischer Maßnahmen (TOMs) entscheidend:

### Zugangskontrolle
- Starke Authentifizierungsmechanismen (MFA)
- Autorisierungskonzepte auf Basis des Least-Privilege-Prinzips
- Passwort-Richtlinien und -Management
- Protokollierung von Zugriffen

### Datensicherheit
- Verschlüsselung von Daten (in Ruhe und in Bewegung)
- TLS für Datenübertragungen
- Festplattenverschlüsselung
- Datenbankverschlüsselung
- Sichere Schlüsselverwaltung

### Netzwerksicherheit
- Segmentierung von Netzwerken
- Firewalls und IDS/IPS-Systeme
- VPN für Remote-Zugriff
- Absicherung von Schnittstellen zu externen Systemen

### Logging und Monitoring
- Zentrale Protokollierung
- Alarmierung bei Anomalien
- Regelmäßige Überprüfung der Protokolle
- Aufbewahrung von Protokollen gemäß gesetzlicher Anforderungen

## 📝 Datenschutz-Anforderungen für DevOps

### Privacy by Design und Privacy by Default

```
┌────────────────────────────┐
│     Privacy by Design      │
├────────────────────────────┤
│ • In jeder Phase beachten  │
│ • Architektur-Review       │
│ • Threat Modeling          │
│ • Risikobasierter Ansatz   │
└────────────────────────────┘
```

**Implementierung in DevOps:**
- Integration von Datenschutzanforderungen in User Stories
- Automatisierte Datenschutz-Tests in CI/CD-Pipelines
- Datenklassifizierung von Anfang an
- Standardmäßige Verschlüsselung sensibler Daten

### DPIA (Datenschutz-Folgenabschätzung)

Für risikoreiche Verarbeitungen ist eine Datenschutz-Folgenabschätzung (DPIA) erforderlich:

1. Systematische Beschreibung der Verarbeitungsvorgänge
2. Bewertung der Notwendigkeit und Verhältnismäßigkeit
3. Identifikation und Bewertung von Risiken
4. Maßnahmen zur Risikominimierung

> [!TIP]
> Integriere die DPIA in frühen Phasen des Software-Entwicklungszyklus, um teure Änderungen in späteren Phasen zu vermeiden.

## 🧪 Datenschutz-Vorfälle und Reaktion

### Definition eines Datenschutzvorfalls
Ein Sicherheitsvorfall, der zur Vernichtung, zum Verlust, zur Veränderung oder zur unbefugten Offenlegung personenbezogener Daten führt.

### Reaktionsplan
1. **Erkennung**: Monitoring-Systeme konfigurieren
2. **Einschätzung**: Schwere und Umfang des Vorfalls bewerten
3. **Eindämmung**: Sofortige Maßnahmen zur Begrenzung des Schadens
4. **Meldung**: Bei hohem Risiko innerhalb von 72 Stunden an Aufsichtsbehörde
5. **Dokumentation**: Vollständige Dokumentation des Vorfalls
6. **Learnings**: Verbesserungsmaßnahmen

## 📊 Nachweise und Audits

### Nachweispflicht
Die DSGVO erfordert den Nachweis der Einhaltung (Rechenschaftspflicht):

- **Verarbeitungsverzeichnis**: Dokumentation aller Datenverarbeitungsaktivitäten
- **Risikobewertungen**: Regelmäßige Bewertung von Datenschutzrisiken
- **Datenschutz-Folgenabschätzungen**: Für risikoreiche Verarbeitungen
- **Technische Dokumentation**: Dokumentation der implementierten Maßnahmen

### Technische Nachweise
- Konfigurationsmanagement mit versionierten Änderungen
- Automatisierte Compliance-Tests
- Protokollierung von Zugriffen und Änderungen
- Dokumentation von Sicherheitsmaßnahmen

## 💾 Datenverarbeitung in der Cloud

Bei der Nutzung von Cloud-Diensten:

- **Auftragsverarbeitungsverträge**: Mit allen Cloud-Anbietern
- **Datenübermittlung**: Besondere Anforderungen bei Datentransfer außerhalb der EU
- **Verschlüsselung**: Kundenseitige Verschlüsselung für höchste Sicherheit
- **Isolation**: Trennung von Mandanten sicherstellen
- **Exit-Strategie**: Plan für Datenmigration und -löschung

## 🔄 Praktische Umsetzung

### Checkliste für Systemadministratoren
- [ ] Verschlüsselung für sensible Daten implementieren
- [ ] Zugriffsrechte regelmäßig überprüfen
- [ ] Audit-Logging aktivieren
- [ ] Automatische Löschung nach Ablauf der Aufbewahrungsfristen
- [ ] Backups verschlüsseln
- [ ] Sichere Authentifizierungsmechanismen implementieren
- [ ] Patch-Management-Prozess etablieren

### Tools für DSGVO-Compliance
- **Data Discovery**: Tools zur Identifizierung personenbezogener Daten (z.B. Varonis, BigID)
- **Zugriffsmanagement**: IAM-Lösungen (z.B. Okta, Azure AD)
- **Compliance-Monitoring**: Automatisierte Compliance-Checks (z.B. Graylog mit DSGVO-Dashboards)
- **Verschlüsselung**: Werkzeuge für Datenverschlüsselung (z.B. Vault, LUKS)

## Verwandte Themen
- [[600 Security/640 Compliance & Governance|Compliance & Governance]]
- [[600 Security/643 Compliance Automation|Compliance Automation]]
- [[600 Security/652 Secret Management|Secret Management]]
- [[600 Security/602 Identity & Access Management|Identity & Access Management]] 
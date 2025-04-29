---
tags: [security, threat-intelligence, soc, ciso]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
---

# Threat Intelligence

> [!INFO]
> Threat Intelligence (TI) befasst sich mit der Sammlung, Analyse und Nutzung von Informationen über Bedrohungsakteure, ihre Taktiken, Techniken und Verfahren (TTPs), um die Cybersicherheit einer Organisation zu verbessern.

## 📋 Grundlagen der Threat Intelligence

### Arten von Threat Intelligence

Threat Intelligence wird in verschiedene Kategorien unterteilt:

1. **Strategische Threat Intelligence**:
   - Für C-Level und strategische Entscheidungsträger
   - Langfristige Trends und Muster
   - Geopolitische Faktoren und ihre Auswirkungen
   - Branchenspezifische Bedrohungen

2. **Taktische Threat Intelligence**:
   - Für Security-Analysten und Incident-Response-Teams
   - TTPs (Taktiken, Techniken und Prozeduren) von Angreifern
   - MITRE ATT&CK-Framework-Mapping
   - Bedrohungsindikatoren (IoCs)

3. **Operative Threat Intelligence**:
   - Für SOC-Teams und Incident-Response
   - Aktuelle Kampagnen und Aktivitäten von Bedrohungsakteuren
   - Kontext für laufende oder unmittelbar bevorstehende Angriffe
   - Spezifische Bedrohungen für die Organisation

4. **Technische Threat Intelligence**:
   - Für Security-Tools und Automatisierung
   - Technische Indikatoren (IP-Adressen, Domains, Hashes)
   - Signaturen für Erkennungsregeln
   - Exploits und Schwachstellen

### TI-Lebenszyklus

```
┌───────────────────────────────────────────────────────────────────┐
│                    Threat Intelligence Lifecycle                  │
├───────────┬───────────┬───────────┬───────────┬───────────────────┤
│ Planning  │ Collection│ Processing│ Analysis  │ Dissemination     │
│ & Direction│          │           │           │ & Feedback        │
└───────────┴───────────┴───────────┴───────────┴───────────────────┘
```

1. **Planung und Zielsetzung**: Definieren der Intelligence-Anforderungen
2. **Sammlung**: Datenerfassung aus verschiedenen Quellen
3. **Verarbeitung**: Umwandlung der Rohdaten in ein nutzbares Format
4. **Analyse**: Interpretation der Daten zur Schaffung von Kontext
5. **Verbreitung**: Bereitstellung der Erkenntnisse für die entsprechenden Stakeholder
6. **Feedback**: Kontinuierliche Verbesserung des Prozesses

## 🔍 Threat Intelligence-Quellen

### Open-Source Intelligence (OSINT)

```bash
# OSINT-Tools für Domain-Untersuchungen
whois example.com
dig example.com ANY
amass enum -d example.com
subfinder -d example.com

# OSINT für IP-Adressen
shodan host 8.8.8.8
censys search "ip:8.8.8.8"
```

**Wichtige OSINT-Quellen:**
- **AlienVault OTX**: Open Threat Exchange
- **MISP**: Malware Information Sharing Platform
- **VirusTotal**: Datei- und URL-Analyse
- **Shodan/Censys**: Internet-Scanning-Plattformen
- **PhishTank**: Phishing-Datenbank
- **Abuse.ch**: Verschiedene Feeds (URLhaus, MalwareBazaar)
- **GitHub Security Lab**: Schwachstellen und Exploits
- **Feodo Tracker**: Bot-C2-Server

### Commercial Threat Intelligence

- **Mandiant Threat Intelligence**: Umfassende APT-Berichterstattung
- **Recorded Future**: Automatisierte Echtzeitanalyse
- **CrowdStrike Intelligence**: Bedrohungsakteure und TTPs
- **Digital Shadows**: Dark Web-Monitoring
- **IBM X-Force Exchange**: Bedrohungsdaten und Analysen

### Government & CERT Sources

- **US-CERT/CISA**: Berichte und Bulletins
- **ENISA**: Europäische Cyber-Sicherheitsbehörde
- **CERT-EU**: Computer Emergency Response Team für EU-Institutionen
- **BSI**: Bundesamt für Sicherheit in der Informationstechnik
- **NCSC**: National Cyber Security Centre (UK)

## 💻 TI-Integration in Security Operations

### SIEM-Integration

```yaml
# Logstash-Konfiguration für TI-Feed-Integration
input {
  http_poller {
    urls => {
      malware_domains => {
        method => get
        url => "https://malwaredomains.com/files/justdomains.txt"
        headers => {
          Accept => "text/plain"
        }
        interval => 3600
      }
    }
    codec => plain
    metadata_target => "http_poller_metadata"
  }
}

filter {
  if [http_poller_metadata][name] == "malware_domains" {
    split { field => "message" }
    mutate {
      add_field => { "indicator_type" => "domain" }
      add_field => { "feed_name" => "malwaredomains" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "threat_intel-%{+YYYY.MM.dd}"
  }
}
```

**Best Practices:**
- Korrelation von Indikatoren mit Netzwerk- und Endpoint-Ereignissen
- Prioritätsbasierte Alarme für hochwertige Indikatoren
- Automatisierte Aktualisierung der SIEM-Regeln
- TI-Kontext in Alarmen und Dashboards
- Historical hunting mit neuen Indikatoren

### Firewalls und IDS/IPS

```bash
# Snort-Regel basierend auf Threat Intelligence
alert tcp any any -> any 80 (msg:"Malicious Domain Access"; content:"Host: "; content:"evil-domain.com"; pcre:"/Host: .*evil-domain\.com/"; classtype:trojan-activity; sid:1000001; rev:1;)

# Suricata-Regel mit Reputation-Liste
drop ip [25.25.25.0/24,26.26.26.0/24] any -> $HOME_NET any (msg:"Bekannte Angreifer"; classtype:misc-attack; sid:2000001; rev:1;)

# Palo Alto Network Security Policy mit TI
set rulebase security rules "Block-Malicious" source any destination any application any service any from trust to untrust action deny profile-setting group "Threat-Prevention" log-setting "Log-Everything"
```

**Best Practices:**
- Automatische Aktualisierung von Blockier-Listen
- Kategorisierung von Indikatoren nach Schweregrad
- Implementierung von Rate-Limiting für häufig auftretende Falschmeldungen
- Fokus auf hochwertigen Indikatoren
- Quarantäne- vs. Blockierungsstrategien

### Endpoint Security

```powershell
# PowerShell - OpenIOC-Integration
$iocXml = Get-Content -Path "malware_indicators.ioc"
$iocData = [xml]$iocXml
$hashes = $iocData.SelectNodes("//IndicatorItem[Context/@search='FileItem/Md5sum']")

# Endpoint-Scan nach bekannten Hashes
foreach ($hash in $hashes) {
    $md5 = $hash.Context.Content
    Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue | Get-FileHash -Algorithm MD5 | Where-Object Hash -eq $md5
}
```

**Best Practices:**
- EDR-Integration mit Threat Intelligence-Feeds
- Automatische Isolation bei Erkennung hochwertiger Indikatoren
- Periodische Scans auf bekannte IOCs
- TI-basierte Verhaltensanalyse
- Retrospektive Analysen neuer Indikatoren

## 🔄 Threat Hunting mit TI

### Hypothesis-Based Hunting

```sql
-- Example SIEM Query based on TI TTPs (MITRE ATT&CK T1003 - Credential Dumping)
SELECT timestamp, hostname, process_name, command_line
FROM process_events
WHERE 
  (process_name LIKE '%mimikatz%' OR 
   process_name LIKE '%pwdump%' OR 
   process_name LIKE '%gsecdump%') OR
  (command_line LIKE '%lsass%dump%' OR 
   command_line LIKE '%wce.exe%' OR 
   command_line LIKE '%procdump%')
ORDER BY timestamp DESC
```

**Best Practices:**
- MITRE ATT&CK-Framework als Basis für Hunting-Hypothesen
- Ausrichtung auf bekannte Angriffsmuster der Gegner
- Kombination von IOC- und TTP-basiertem Hunting
- Iterativer Ansatz mit kontinuierlicher Verfeinerung
- Dokumentation der Ergebnisse zur Verbesserung der TI

### IOC-Based Hunting

```bash
# Suche nach bekannten böswilligen Domains in DNS-Logs
grep -E "evil-domain1\.com|evil-domain2\.com|evil-domain3\.net" /var/log/dns.log

# Yara-Regel basierend auf TI
rule APT_Group_Malware {
    meta:
        description = "Detects malware from APT Group X"
        threat_level = 8
        author = "Threat Intelligence Team"
    strings:
        $str1 = "unique_string_1" ascii wide
        $str2 = "unique_string_2" ascii wide
        $code1 = { 45 B8 3F 45 17 CB 88 1F }
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (all of ($str*) or $code1)
}
```

**Best Practices:**
- Fokus auf aktuelle und relevante Indikatoren
- Kombination verschiedener Indikatortypen
- Priorisierung basierend auf Risikobewertung
- Automatisierte Periodische Scans mit neuen IOCs
- Skalierbare Suchabfragen für große Umgebungen

## 📊 TI-Plattformen und -Formate

### STIX/TAXII

```json
// STIX 2.1 Beispiel
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2023-04-06T20:03:00.000Z",
  "modified": "2023-04-06T20:03:00.000Z",
  "name": "Malicious domain indicator",
  "description": "Domain used in phishing campaign",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'evil-domain.com']",
  "pattern_type": "stix",
  "valid_from": "2023-04-06T20:03:00Z",
  "kill_chain_phases": [
    {
      "kill_chain_name": "lockheed-martin-cyber-kill-chain",
      "phase_name": "delivery"
    }
  ]
}
```

**STIX-Objekte:**
- **SDO (STIX Domain Objects)**: Bedrohungsakteure, Kampagnen, Indikatoren
- **SRO (STIX Relationship Objects)**: Beziehungen zwischen SDOs
- **SCO (STIX Cyber Observable)**: Technische Beobachtungen (IPs, Hashes)

**TAXII-Services:**
- **Collections**: Gruppen von CTI-Objekten
- **Channels**: Push-Mechanismen für neue Intelligenz
- **API Roots**: Zugangspunkte für TAXII-Services

### TI-Plattformen

**Open-Source-Plattformen:**
- **OpenCTI**: Umfassende Open-Source-TI-Plattform
- **MISP**: Malware Information Sharing Platform
- **TheHive & Cortex**: Incident Response mit TI-Integration
- **CIF (Collective Intelligence Framework)**: Aggregation und Sharing

**Kommerzielle Plattformen:**
- **ThreatConnect**: TI-Plattform mit Orchestrierung
- **ThreatQuotient**: TI-Operationen und Management
- **Anomali ThreatStream**: Intelligenzaggregation und -analyse
- **EclecticIQ Platform**: TI-Management und -Collaboration

## 🔐 Threat Intelligence Sharing

### ISACs und ISAOs

- **Finanzielle Institutionen**: FS-ISAC
- **Gesundheitswesen**: H-ISAC
- **Energie**: E-ISAC
- **Automobilindustrie**: Auto-ISAC
- **Information Technology**: IT-ISAC

**Best Practices:**
- Aktive Teilnahme an branchenspezifischen Gruppen
- Bidirektionaler Austausch (Geben und Nehmen)
- Menschliche Beziehungen aufbauen
- Standard-Formate für den Austausch verwenden
- Traffic-Light-Protocol (TLP) für die Klassifizierung von Daten

### Sharing-Richtlinien und -Protokolle

```yaml
# TLP-Klassifizierungsbeispiele
- TLP:RED: 
    description: "Nur direkte Teilnehmer"
    handling: "Nur mündliche Weitergabe, keine Speicherung"
- TLP:AMBER: 
    description: "Begrenzter Austausch"
    handling: "Nur innerhalb der Organisation und mit direkten Partnern"
- TLP:GREEN: 
    description: "Community-Austausch"
    handling: "Innerhalb der Community, nicht öffentlich"
- TLP:WHITE: 
    description: "Unbeschränkte Verteilung"
    handling: "Öffentlich teilbar, unter Einhaltung von Urheberrechten"
```

**Sharing-Plattformen:**
- **MISP-Instanzen**: Organisationsübergreifende MISP-Synchronisation
- **STIX/TAXII-Server**: Standardisierter Austausch
- **Trusted Groups**: Geschlossene Gruppen für sensiblen Austausch
- **Information Sharing Agreements**: Rechtliche Grundlagen für TI-Sharing

## 📝 Building a TI-Program

### Aufbau eines TI-Teams

```
┌─────────────────────────────────────────────────────────┐
│               Threat Intelligence Team                  │
├─────────────────┬─────────────────┬─────────────────────┤
│ Collection &    │ Analysis &      │ Integration &       │
│ Processing      │ Production      │ Operations          │
├─────────────────┼─────────────────┼─────────────────────┤
│• OSINT-Sammlung │• Analyse von    │• SIEM-Integration   │
│• Feed-Management│  Rohdaten       │• Firewall/IDS       │
│• Datenbereinig. │• Berichte       │• Hunting-Support    │
│• Deduplication  │• Empfehlungen   │• Automatisierung    │
└─────────────────┴─────────────────┴─────────────────────┘
```

**Kernrollen:**
- **TI-Analyst**: Primäre Analyse und Berichterstattung
- **TI-Engineer**: Integration und Automatisierung
- **TI-Manager**: Programm-Management und Strategie
- **OSINT-Spezialist**: Spezialisierung auf offene Quellen
- **Malware-Analyst**: Reverse Engineering und Malware-Analyse

### TI Requirements

Bei der Definition von TI-Anforderungen sollte auf das Format "PIR" (Priority Intelligence Requirements) und "IR" (Intelligence Requirements) geachtet werden:

**PIR-Beispiele:**
- Welche Bedrohungsakteure zielen auf unsere Branche ab?
- Welche TTPs werden gegen unsere kritischen Assets eingesetzt?
- Welche Schwachstellen werden aktiv gegen unsere Technologien ausgenutzt?

**IR-Beispiele:**
- Welche Domains und IPs sind mit Kampagne X verbunden?
- Welche Malware wird bei Angriffen auf den Finanzsektor eingesetzt?
- Welche Phishing-Taktiken werden derzeit beobachtet?

### Metrics und KPIs

```
┌─────────────────────────────────────────────────────────┐
│               Threat Intelligence Metrics               │
├─────────────────┬─────────────────┬─────────────────────┤
│ Input Metrics   │ Process Metrics │ Output Metrics      │
├─────────────────┼─────────────────┼─────────────────────┤
│• # TI-Feeds     │• Bearbeitungs-  │• True Positive Rate │
│• # Indikatoren  │  zeit           │• Mean Time to Detect│
│• Quellenvielfalt│• Deduplizierung │• Verhinderte Angrif.│
│• Quellenzuverl. │• Analysegeschw. │• Geschäftl. Einfluss│
└─────────────────┴─────────────────┴─────────────────────┘
```

**Best Practices:**
- Quantitative und qualitative Metriken kombinieren
- Zeiteinsparungen durch TI messen
- Proaktive Maßnahmen aufgrund von TI verfolgen
- Executive Reporting mit Business Impact
- Kontinuierliche Verbesserung auf Basis der Metriken

## 🔍 Advanced TI-Techniken

### Adversary Emulation

```yaml
# CALDERA (MITRE) Emulation Plan Format
adversary:
  name: APT29_Emulation
  description: "Emulation of APT29 TTPs"
  phases:
    - name: Initial Access
      steps:
        - technique: T1566.001
          description: "Spearphishing Attachment"
          commands:
            - platform: windows
              command: "powershell.exe -ExecutionPolicy Bypass -C ..."
    - name: Execution
      steps:
        - technique: T1059.001
          description: "PowerShell"
          commands:
            - platform: windows
              command: "powershell.exe -nop -w hidden -c ..."
```

**Best Practices:**
- Purple Team-Übungen mit TI-basierter Emulation
- MITRE ATT&CK als Framework für Emulationspläne
- Realistische TTP-Umsetzung mit tatsächlichen Tools
- Messung der Erkennungs- und Reaktionsfähigkeiten
- Iterative Verbesserung der Sicherheitskontrollen

### Diamond Model Analytics

```
┌─────────────────────────────────────────────────────────┐
│                 Diamond Model                           │
│                                                         │
│                  Adversary                              │
│                      ◆                                  │
│                     ╱ ╲                                 │
│                    ╱   ╲                                │
│                   ╱     ╲                               │
│              ◆───────────◆                              │
│         Capability     Infrastructure                   │
│              ◆───────────◆                              │
│                   ╲     ╱                               │
│                    ╲   ╱                                │
│                     ╲ ╱                                 │
│                      ◆                                  │
│                    Victim                               │
└─────────────────────────────────────────────────────────┘
```

**Analytischer Ansatz:**
- **Adversary**: Bedrohungsakteure und ihre Motivationen
- **Capability**: Werkzeuge, Taktiken und Techniken
- **Infrastructure**: Verwendete Ressourcen und Infrastruktur
- **Victim**: Ziele und deren Eigenschaften
- **Pivot-Punkte**: Verbindungen zwischen verschiedenen Angriffen

### Threat Hunting Frameworks

```yaml
# Hunting Framework basierend auf MITRE ATT&CK
hunt_plan:
  name: "Lateral Movement Detection"
  description: "Suche nach Anzeichen von Lateral Movement"
  tactics:
    - name: "Lateral Movement"
      techniques:
        - id: "T1021.001"
          name: "Remote Desktop Protocol"
          data_sources:
            - "Windows Event Logs (4624, 4625, 4648)"
            - "RDP Session Logs"
          query: |
            SELECT source_host, target_host, username, 
                   timestamp, event_id
            FROM windows_events
            WHERE event_id IN (4624, 4648)
              AND logon_type = 10
              AND NOT username LIKE '%service%'
            ORDER BY timestamp DESC
          indicators:
            - "Ungewöhnliche RDP-Verbindungen"
            - "Verbindungen außerhalb der Geschäftszeiten"
            - "Verbindungen von unerwarteten Quell-IPs"
          response_actions:
            - "Isolation des Quellsystems"
            - "Sperrung des betroffenen Kontos"
            - "Forensische Analyse beider Systeme"
```

**Hunting-Methoden:**
- **TTP-basiertes Hunting**: Basierend auf Angriffstechniken
- **IoC-basiertes Hunting**: Suche nach bekannten Indikatoren
- **Anomalie-basiertes Hunting**: Suche nach ungewöhnlichem Verhalten
- **Situatives Hunting**: Reaktion auf aktuelle Bedrohungen
- **Hypothesen-getriebenes Hunting**: Wissenschaftlicher Ansatz

## Verwandte Themen
- [[600 Security/650 SIEM-Systeme|SIEM-Systeme]]
- [[600 Security/671 Incident Response|Incident Response]]
- [[600 Security/673 Threat Hunting|Threat Hunting]]
- [[600 Security/675 SOC Operations|SOC Operations]]
- [[600 Security/635 Blue Team|Blue Team Operations]] 
# Server Inventar Generator

Dieses Skript sammelt automatisch Informationen über Server in verschiedenen Cloud-Umgebungen (Hetzner Cloud, AWS und Azure) und erstellt ein strukturiertes Dokument in Markdown und HTML-Format.

## Voraussetzungen

- Python 3.6+
- Umgebungsvariablen mit API-Zugangsdaten:
  ```
  # Hetzner Cloud
  export HCLOUD_TOKEN=your_hetzner_cloud_token
  export HETZNER_DNS_API_TOKEN=your_hetzner_dns_token
  
  # AWS
  export AWS_ACCESS_KEY_ID=your_aws_access_key
  export AWS_SECRET_ACCESS_KEY=your_aws_secret_key
  export AWS_SESSION_TOKEN=your_aws_session_token  # optional
  
  # Azure (optional)
  export AZURE_TENANT_ID=your_azure_tenant_id
  export AZURE_CLIENT_ID=your_azure_client_id
  export AZURE_CLIENT_SECRET=your_azure_client_secret
  ```

- Fehlende Python-Abhängigkeiten werden automatisch installiert

## Verwendung

```bash
# Skript ausführen mit Standardausgabeverzeichnis (./output)
python server_inventory.py

# Skript mit benutzerdefiniertem Ausgabeverzeichnis
python server_inventory.py -o /pfad/zum/ausgabeverzeichnis
```

## Ausgabe

Das Skript generiert zwei Dateien im angegebenen Ausgabeverzeichnis:

1. `server_inventory_YYYYMMDD.md` - Markdown-Dokument
2. `server_inventory_YYYYMMDD.html` - HTML-Dokument mit einfachem CSS-Styling

Beide Dateien enthalten die folgenden Informationen zu jedem Server, gruppiert nach Cloud-Anbieter:

- Server-Name
- Betriebssystem
- FQDN (falls verfügbar)
- IP-Adresse (IPv4/IPv6)
- Status
- Region
- Server-Typ

## Erweiterungen

Das Skript kann je nach Bedarf angepasst werden, z.B.:

- Zusätzliche Cloud-Anbieter hinzufügen
- Weitere Server-Informationen erfassen
- Andere Ausgabeformate hinzufügen (z.B. CSV, JSON, Excel)
- Automatisches Senden der Berichte per E-Mail

## Fehlerbehebung

Wenn das Skript für einen Cloud-Anbieter Fehler meldet:

1. Prüfen Sie, ob alle erforderlichen Umgebungsvariablen korrekt gesetzt sind
2. Prüfen Sie, ob die API-Zugangsdaten gültige Berechtigungen haben
3. Überprüfen Sie die Netzwerkverbindung zu den Cloud-Anbietern 
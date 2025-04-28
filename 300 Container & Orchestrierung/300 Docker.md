# Docker

Tags: #tool #container

## Überblick
Docker ist eine Open-Source-Plattform, die die Erstellung, Bereitstellung und Ausführung von Anwendungen in Containern ermöglicht. Container sind leichtgewichtige, isolierte Umgebungen, die alle notwendigen Abhängigkeiten für eine Anwendung enthalten.

## Installationsschritte
```bash
# Installation auf Ubuntu
sudo apt update
sudo apt install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io

# Benutzer zur docker-Gruppe hinzufügen (um ohne sudo arbeiten zu können)
sudo usermod -aG docker $USER
# Anmeldung neu starten, damit die Gruppenänderung wirksam wird

# Installation überprüfen
docker --version
docker run hello-world
```

## Grundlegende Konfiguration
### Dockerfile-Beispiel
```dockerfile
FROM ubuntu:20.04

# Umgebungsvariablen setzen
ENV DEBIAN_FRONTEND=noninteractive
ENV APP_HOME=/app

# Pakete installieren
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Arbeitsverzeichnis setzen
WORKDIR $APP_HOME

# Dateien kopieren
COPY requirements.txt .
COPY app/ .

# Abhängigkeiten installieren
RUN pip3 install --no-cache-dir -r requirements.txt

# Port freigeben
EXPOSE 8000

# Startbefehl
CMD ["python3", "app.py"]
```

### Docker Compose Beispiel
```yaml
version: '3'

services:
  web:
    build: ./web
    ports:
      - "8000:8000"
    depends_on:
      - db
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/app
    volumes:
      - ./web:/app

  db:
    image: postgres:13
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=app
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## Wichtige Befehle
```bash
# Images
docker build -t mein-image:tag .           # Image aus Dockerfile bauen
docker images                              # Alle Images auflisten
docker pull nginx:latest                   # Image herunterladen
docker push mein-image:tag                 # Image zu Registry pushen
docker rmi image_id                        # Image löschen

# Container
docker run -d -p 8080:80 --name webserver nginx   # Container starten
docker ps                                  # Laufende Container anzeigen
docker ps -a                               # Alle Container anzeigen
docker stop container_id                   # Container stoppen
docker start container_id                  # Container starten
docker restart container_id                # Container neustarten
docker rm container_id                     # Container löschen
docker logs container_id                   # Container-Logs anzeigen
docker exec -it container_id bash          # Shell im Container öffnen

# Docker Compose
docker-compose up -d                       # Services starten
docker-compose down                        # Services stoppen und entfernen
docker-compose logs                        # Logs aller Services anzeigen
docker-compose ps                          # Status der Services anzeigen

# System
docker system prune                        # Nicht verwendete Ressourcen löschen
docker system df                           # Speichernutzung anzeigen
```

## Best Practices
- Offizielle Basis-Images verwenden
- Multi-Stage-Builds für kleinere Images
- Nicht als Root im Container laufen
- `.dockerignore` Datei verwenden
- Minimale Images mit Alpine oder Scratch
- Eine Anwendung pro Container
- Umgebungsvariablen für Konfiguration nutzen
- Explizite Image-Tags statt `latest` verwenden
- Container unveränderbar (immutable) halten
- Sensible Daten mit Docker Secrets oder externen Tools verwalten
- Gesundheitschecks (HEALTHCHECK) implementieren

## Häufige Probleme und Lösungen
- **Port bereits in Verwendung**: Anderen Port mappen oder bestehenden Container beenden
- **Berechtigungsprobleme**: Volumes mit korrekten Berechtigungen mounten
- **Container startet nicht**: Logs mit `docker logs` prüfen
- **Netzwerkprobleme**: Docker-Netzwerke und DNS-Einstellungen überprüfen
- **Speicherplatzprobleme**: Regelmäßige Bereinigung mit `docker system prune`

## Sicherheitshinweise
- Images regelmäßig scannen (z.B. mit Trivy, Clair)
- Rootless-Modus oder USER-Anweisung verwenden
- Container-Ressourcen limitieren (--memory, --cpu)
- read-only Filesystem wo möglich
- Content-Trust für signierte Images aktivieren
- AppArmor/SELinux-Profile verwenden
- Docker Socket nicht exponieren
- Docker Bench Security regelmäßig ausführen

## Monitoring & Logging
- `docker stats` für Ressourcennutzung
- Prometheus + cAdvisor für Metriken
- Fluentd/Logstash für zentrales Logging
- Logs mit JSON-Treiber strukturieren
- Docker Events überwachen
- Grafana für Visualisierung

## Nützliche Links
- [Docker-Dokumentation](https://docs.docker.com/)
- [Docker Hub](https://hub.docker.com/)
- [Docker Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)

## Verwandte Themen
- [[300 Container & Orchestrierung/310 Kubernetes|Kubernetes]]
- [[300 Container & Orchestrierung/301 Podman|Podman]]
- [[600 Security/612 Container-Sicherheit|Container-Sicherheit]]
- [[400 CI_CD & Automation/402 Container CI/CD|Container CI/CD]] 
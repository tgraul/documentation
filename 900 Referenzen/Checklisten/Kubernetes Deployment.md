---
tags: [kubernetes, deployment, checkliste, container]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
---

# Kubernetes Deployment Checkliste

> [!INFO]
> Diese Checkliste dient als Referenz für Deployments in Kubernetes-Umgebungen.

## 📋 Vor dem Deployment

### Applikation
- [ ] Container-Image gebaut und getestet
- [ ] Image-Tags sind spezifisch (kein `latest`-Tag)
- [ ] Multi-stage Builds für minimale Image-Größe
- [ ] Container läuft nicht als Root-Benutzer
- [ ] Healthchecks (Liveness/Readiness) implementiert
- [ ] Application Secrets externalisiert
- [ ] Umgebungsvariablen definiert
- [ ] Logging konfiguriert

### Kubernetes-Ressourcen
- [ ] Namespace erstellt/vorhanden
- [ ] Deployments/StatefulSets definiert
- [ ] Services definiert 
- [ ] Ingress/Route konfiguriert
- [ ] ConfigMaps erstellt
- [ ] Secrets sicher erstellt
- [ ] PersistentVolumeClaims (falls nötig)
- [ ] ResourceQuotas und LimitRanges definiert
- [ ] RBAC-Rollen und RoleBindings konfiguriert
- [ ] NetworkPolicies definiert

### Sicherheit
- [ ] Container-Image auf Schwachstellen geprüft
- [ ] PodSecurityPolicies/Pod Security Standards berücksichtigt
- [ ] SecurityContext mit Einschränkungen definiert
- [ ] Container sind read-only wo möglich
- [ ] Service-Accounts mit minimalen Berechtigungen
- [ ] Netzwerk-Policies entsprechend Anforderungen

## 🚀 Während des Deployments

- [ ] Staging-Umgebung vor Produktion testen
- [ ] Blue/Green oder Canary-Deployment-Strategie verwenden
- [ ] Deployment-Logs überwachen
- [ ] Ressourcennutzung überwachen
- [ ] Automatische Tests in der Pipeline ausführen
- [ ] Backup erstellen (falls Upgrade eines bestehenden Systems)
- [ ] Kubernetes-Manifeste in Git-Repository speichern

## 🔍 Nach dem Deployment

- [ ] Status der Pods prüfen: `kubectl get pods -n <namespace>`
- [ ] Logs auf Fehler prüfen: `kubectl logs -n <namespace> <pod-name>`
- [ ] Endpoints/Services testen: `kubectl get endpoints -n <namespace>`
- [ ] Frontend/API testen (end-to-end Tests)
- [ ] Monitoring und Alerts aktivieren
- [ ] Performance-Metriken sammeln
- [ ] Logging-Konfiguration verifizieren
- [ ] Dokumentation aktualisieren
- [ ] Kommunikation an betroffene Stakeholder

## 🔄 Rollback-Plan

- [ ] Rollback-Strategie definiert
- [ ] Vorherige Version bekannt und verfügbar
- [ ] Befehle für Rollback dokumentiert:
```bash
# Beispiel Rollback auf vorherige Version
kubectl rollout undo deployment/<deployment-name> -n <namespace>
# Oder auf spezifische Version
kubectl rollout undo deployment/<deployment-name> -n <namespace> --to-revision=<revision>
```
- [ ] Datenbank-Rollback (falls nötig) getestet
- [ ] Kriterien für Rollback-Entscheidung definiert

## 📊 Skalierung und Ressourcen

- [ ] CPU/Memory-Requests festgelegt
- [ ] CPU/Memory-Limits festgelegt
- [ ] HorizontalPodAutoscaler konfiguriert
- [ ] Pod Disruption Budget definiert
- [ ] Ressourcennutzung beobachten und anpassen

## 📝 Checkliste für Spezielle Anwendungsfälle

### Datenbank-Deployments
- [ ] Persistente Volumes konfiguriert
- [ ] Backup-Strategie implementiert
- [ ] Hochverfügbarkeit konfiguriert
- [ ] InitContainers für Dateninitialisierung

### Microservice-Deployments
- [ ] Service-to-Service-Kommunikation konfiguriert
- [ ] Service Mesh (falls vorhanden) konfiguriert
- [ ] Distributed Tracing eingerichtet
- [ ] API-Gateway/Ingress-Controller konfiguriert

## Verwandte Themen
- [[300 Container & Orchestrierung/310 Kubernetes|Kubernetes]]
- [[300 Container & Orchestrierung/311 Helm|Helm]]
- [[600 Security/613 Kubernetes-Sicherheit|Kubernetes-Sicherheit]]
- [[500 Monitoring & Logging/510 Kubernetes Monitoring|Kubernetes Monitoring]] 
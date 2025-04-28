---
tags: [kubernetes, container, orchestrierung]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
verwandte_technologien: [docker, helm]
---

# Kubernetes

Tags: #tool #container #orchestrierung

## Überblick
Kubernetes ist eine Open-Source-Plattform zur Automatisierung, Skalierung und Verwaltung von containerisierten Anwendungen. Es gruppiert Container zu logischen Einheiten für einfache Verwaltung und Discovery.

> [!NOTE]
> Kubernetes wird oft als "k8s" abgekürzt (8 Buchstaben zwischen k und s).

## Installationsschritte
### Minikube (lokale Entwicklung)
```bash
# Installation auf Ubuntu
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
minikube start
```

### kubectl
```bash
# Installation
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

## Grundlegende Konfiguration
```yaml
# Beispiel Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
```

## Wichtige Befehle
```bash
kubectl get pods                      # Zeigt Pods an
kubectl get nodes                     # Zeigt Nodes an
kubectl get deployments               # Zeigt Deployments an
kubectl describe pod <pod-name>       # Zeigt Details eines Pods
kubectl logs <pod-name>               # Zeigt Logs eines Pods
kubectl apply -f <filename.yaml>      # Wendet Konfiguration an
kubectl delete -f <filename.yaml>     # Löscht Ressourcen
kubectl exec -it <pod-name> -- /bin/bash # Shell in Pod öffnen
```

## Best Practices
- Ressourcenlimits für jeden Container festlegen
- Liveness und Readiness Probes konfigurieren
- Immer explizite Image-Tags verwenden, nicht `latest`
- Network Policies implementieren
- RBAC für Zugriffssteuerung nutzen
- Secrets für sensible Daten verwenden
- Namespaces zur logischen Trennung verwenden

> [!TIP]
> Verwende `kubectl explain` um die Struktur von Kubernetes-Ressourcen zu verstehen, z.B. `kubectl explain deployment.spec`

## Häufige Probleme und Lösungen
- **ImagePullBackOff**: Image nicht gefunden oder Zugriffsrechte fehlen
- **CrashLoopBackOff**: Container startet und crasht wiederholt
- **Pending Pods**: Ressourcenmangel oder Node-Affinity-Probleme
- **Evicted Pods**: Ressourcenmangel auf dem Node
- **Connection Refused**: Service/Netzwerkprobleme

> [!WARNING]
> Sei vorsichtig mit `kubectl delete` ohne Namespace-Angabe, da es alle Ressourcen in allen Namespaces löschen kann!

## Sicherheitshinweise
- Immer RBAC für Zugriffssteuerung verwenden
- Container laufen standardmäßig als root - nutze SecurityContext
- PodSecurityPolicies/Pod Security Standards implementieren
- Network Policies für Mikrosegmentierung einsetzen
- Images regelmäßig scannen (z.B. mit Trivy)
- Admission Controller nutzen (z.B. OPA/Gatekeeper)

## Monitoring & Logging
- Prometheus für Metriken
- Grafana für Dashboards
- ELK/EFK Stack für Logging
- Loki als leichtgewichtige Log-Aggregation
- Jaeger/Tempo für Tracing

## Nützliche Links
- [Offizielle Kubernetes-Dokumentation](https://kubernetes.io/docs/home/)
- [Kubernetes Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [Helm Hub](https://artifacthub.io/) für Kubernetes-Pakete

## Verwandte Themen
- [[300 Container & Orchestrierung/300 Docker|Docker]]
- [[300 Container & Orchestrierung/311 Helm|Helm]]
- [[600 Security/612 Container-Sicherheit|Container-Sicherheit]]
- [[600 Security/613 Kubernetes-Sicherheit|Kubernetes-Sicherheit]] 
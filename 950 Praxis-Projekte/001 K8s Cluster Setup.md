---
tags: [kubernetes, project, infrastructure, container]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
---

# Kubernetes-Cluster Aufbau mit kubeadm

> [!NOTE]
> Dokumentation des Projekts zur Einrichtung eines selbstverwalteten Kubernetes-Clusters mit kubeadm.

## 📋 Überblick

**Projektziel:** Aufbau eines hochverfügbaren Kubernetes-Clusters für interne Entwicklungsumgebungen mit drei Master-Nodes und mehreren Worker-Nodes.

**Zeitraum:** 01.09.2023 - 15.09.2023

**Beteiligte Systeme:**
- 3x Master-Nodes (Ubuntu 22.04, 4 vCPUs, 8GB RAM)
- 5x Worker-Nodes (Ubuntu 22.04, 8 vCPUs, 16GB RAM)
- HAProxy für API-Server Load Balancing
- NFS für persistente Volumes
- Calico als CNI-Plugin

## 🏗️ Architektur

```
                ┌─────────────┐
                │   HAProxy   │
                └──────┬──────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
┌──────▼─────┐  ┌──────▼─────┐  ┌──────▼─────┐
│  Master-1  │  │  Master-2  │  │  Master-3  │
└──────┬─────┘  └──────┬─────┘  └──────┬─────┘
       │               │               │
       └───────────────┼───────────────┘
                       │
   ┌─────────┬─────────┼─────────┬─────────┐
   │         │         │         │         │
┌──▼──┐  ┌───▼─┐   ┌───▼─┐   ┌───▼─┐   ┌───▼─┐
│Node1│  │Node2│   │Node3│   │Node4│   │Node5│
└─────┘  └─────┘   └─────┘   └─────┘   └─────┘
```

## 📝 Implementierungsdetails

### 1. Vorbereitung der Systeme

Auf allen Nodes:

```bash
# Swap deaktivieren
sudo swapoff -a
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab

# Netzwerkeinstellungen
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sudo sysctl --system

# Installation von Docker
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# containerd konfigurieren
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
sudo systemctl restart containerd

# Installation von kubeadm, kubelet und kubectl
sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet=1.25.0-00 kubeadm=1.25.0-00 kubectl=1.25.0-00
sudo apt-mark hold kubelet kubeadm kubectl
```

### 2. HAProxy Setup für Load Balancing

Auf dem HAProxy-Server:

```conf
# /etc/haproxy/haproxy.cfg
frontend kubernetes-frontend
    bind *:6443
    mode tcp
    option tcplog
    default_backend kubernetes-backend

backend kubernetes-backend
    mode tcp
    option tcp-check
    balance roundrobin
    server master-1 192.168.1.101:6443 check fall 3 rise 2
    server master-2 192.168.1.102:6443 check fall 3 rise 2
    server master-3 192.168.1.103:6443 check fall 3 rise 2
```

### 3. Initialisierung des ersten Master-Nodes

```bash
# First Master
sudo kubeadm init --control-plane-endpoint "192.168.1.100:6443" --upload-certs --pod-network-cidr=10.244.0.0/16

# Nach erfolgreicher Initialisierung
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

### 4. Weitere Master-Nodes hinzufügen

```bash
# Befehl wurde bei der Initialisierung des ersten Masters ausgegeben
sudo kubeadm join 192.168.1.100:6443 --token xxx --discovery-token-ca-cert-hash sha256:xxx --control-plane --certificate-key xxx
```

### 5. Worker-Nodes hinzufügen

```bash
# Befehl wurde bei der Initialisierung des ersten Masters ausgegeben
sudo kubeadm join 192.168.1.100:6443 --token xxx --discovery-token-ca-cert-hash sha256:xxx
```

### 6. Calico CNI Installation

```bash
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
```

### 7. Storage-Klasse für NFS einrichten

```yaml
# nfs-storageclass.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-storage
provisioner: kubernetes.io/nfs
parameters:
  server: 192.168.1.200
  path: /exports/kubernetes
  readOnly: "false"
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: nfs-pv
spec:
  capacity:
    storage: 500Gi
  accessModes:
    - ReadWriteMany
  persistentVolumeReclaimPolicy: Retain
  storageClassName: nfs-storage
  nfs:
    server: 192.168.1.200
    path: /exports/kubernetes
```

## 🧪 Tests und Validierung

- [x] Alle Nodes im Cluster sichtbar: `kubectl get nodes`
- [x] Alle System-Pods laufen: `kubectl get pods -n kube-system`
- [x] Netzwerk-Konnektivität zwischen Pods
- [x] Master-HA: Cluster bleibt funktionsfähig nach Ausfall eines Masters
- [x] Persistente Volumes funktionieren
- [x] Deployment-Test mit einer Beispielanwendung

## 📈 Monitoring und Wartung

- Installierte Prometheus und Grafana für Cluster-Monitoring
- Konfigurierte Alertmanager für kritische Benachrichtigungen
- Wartungsfenster jeden ersten Mittwoch im Monat
- Automatisches Backup der etcd-Datenbank täglich

## 💡 Lessons Learned

- HAProxy sollte redundant aufgesetzt werden, um SPOF zu vermeiden
- Calico benötigt mehr Ressourcen als erwartet
- Bei NFS-Volumes können Performance-Probleme auftreten
- CNI-Installation sollte vor dem Hinzufügen weiterer Nodes erfolgen
- Richtige Größe der Worker-Nodes ist entscheidend für Stabilität

## 📚 Referenzen und Links

- [Kubernetes-Dokumentation zu kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)
- [Calico-Dokumentation](https://docs.projectcalico.org/getting-started/kubernetes/quickstart)
- [[300 Container & Orchestrierung/310 Kubernetes|Kubernetes-Dokumentation]]
- [[900 Referenzen/Checklisten/Kubernetes Deployment|Kubernetes-Deployment-Checkliste]]

## ✅ Checkliste für Produktivsetzung

- [x] Alle Nodes auf gleichem Patch-Level
- [x] Netzwerk-Richtlinien implementiert
- [x] Monitoring und Alerting eingerichtet
- [x] Backup-Strategie implementiert
- [x] Security-Hardening durchgeführt
- [x] Dokumentation erstellt
- [x] Zugriff für das Team eingerichtet 
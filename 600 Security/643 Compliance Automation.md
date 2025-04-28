---
tags: [security, compliance, automation, devops, devsecops, ciso]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
---

# Compliance Automation

> [!INFO]
> Compliance Automation befasst sich mit der Automatisierung von Compliance-Anforderungen in DevOps-Umgebungen. Dieser Ansatz ermöglicht es, Compliance als Code zu implementieren und kontinuierlich zu überprüfen.

## 📋 Grundlagen der Compliance Automation

Compliance Automation verfolgt das Ziel, manuelle Compliance-Prüfungen durch automatisierte Prozesse zu ersetzen. Dies ermöglicht:

- **Kontinuierliche Compliance** anstelle punktueller Audits
- **Reproduzierbare Ergebnisse** durch standardisierte Tests
- **Frühzeitiges Erkennen** von Compliance-Verstößen
- **Dokumentierte Nachweise** für Audit-Anforderungen
- **Effiziente Skalierung** der Compliance-Überwachung

### Das Continuous Compliance Modell

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Continuous Compliance                           │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────┤
│ Compliance  │ Compliance  │ Compliance  │ Compliance  │ Compliance  │
│ as Code     │ Pipeline    │ Testing     │ Monitoring  │ Reporting   │
└─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘
```

## 🔄 Compliance as Code (CaC)

### Definition und Vorteile

Compliance as Code bedeutet, Compliance-Anforderungen in maschinenlesbarer Form zu definieren, die automatisch überprüft werden kann.

**Vorteile:**
- Versionierbare Compliance-Regeln
- Wiederverwendbarkeit über Systeme hinweg
- Selbstdokumentierende Standards
- Integrierbar in DevOps-Workflows

### Implementierungsansätze

**1. Policy as Code:**
```yaml
# Beispiel: OPA Rego Policy für Kubernetes
package kubernetes.admission
deny[msg] {
  input.request.kind.kind == "Pod"
  not input.request.object.spec.securityContext.runAsNonRoot
  msg := "Pods must run as non-root user"
}
```

**2. Compliance-Prüfungen in Infrastructure as Code:**
```hcl
# Terraform mit AWS-Compliance-Checks
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "compliant-bucket"
  acl    = "private"
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
}
```

**3. Security Posture Management:**
```yaml
# Kubernetes Network Policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## 🔍 Compliance-Scanning in der CI/CD-Pipeline

### Integration in den CI/CD-Workflow

Compliance-Checks sollten in verschiedenen Phasen der CI/CD-Pipeline integriert werden:

```
┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
│   Code    │────▶│   Build   │────▶│    Test   │────▶│  Deploy   │────▶│  Operate  │
└───────────┘     └───────────┘     └───────────┘     └───────────┘     └───────────┘
      │                │                 │                 │                  │
      ▼                ▼                 ▼                 ▼                  ▼
┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
│SAST & SCA │     │  Image    │     │Security & │     │Config &   │     │ Runtime   │
│Scans      │     │  Scanning │     │Comp. Tests│     │IAM Checks │     │ Monitoring│
└───────────┘     └───────────┘     └───────────┘     └───────────┘     └───────────┘
```

### Jenkins Pipeline Beispiel

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Dependency Check') {
            steps {
                sh 'dependency-check --project "My Project" --scan .'
            }
        }
        
        stage('Static Analysis') {
            steps {
                sh 'sonarqube-scanner'
            }
        }
        
        stage('Infrastructure Compliance') {
            steps {
                sh 'terraform init'
                sh 'terraform plan -out=tfplan'
                sh 'terraform-compliance -p tfplan -f ./compliance-policies/'
            }
        }
        
        stage('Container Security') {
            steps {
                sh 'docker build -t myapp:latest .'
                sh 'trivy image --severity HIGH,CRITICAL myapp:latest'
            }
        }
        
        stage('Deploy') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                sh 'terraform apply -auto-approve tfplan'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '**/compliance-reports/**/*', allowEmptyArchive: true
        }
    }
}
```

### GitHub Actions Beispiel

```yaml
name: Compliance Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Security scan for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
      
      - name: Infrastructure compliance check
        uses: terraform-linters/tflint-action@master
        
      - name: Kubernetes manifest validation
        uses: instrumenta/kubeval-action@master
        with:
          files: k8s/*.yaml
      
      - name: Upload compliance reports
        uses: github/codeql-action/upload-sarif@v1
        with:
          sarif_file: trivy-results.sarif
```

## 🛠️ Tools für Compliance Automation

### Infrastruktur-Compliance

| Tool | Beschreibung | Anwendungsbereich |
|------|--------------|-------------------|
| Terraform Sentinel | Policy as Code für Terraform | IaC Compliance |
| Checkov | Static Code Analysis für IaC | Terraform, CloudFormation, Kubernetes |
| tfsec | Security Scanner für Terraform | Terraform Security |
| Kyverno | Policy Engine für Kubernetes | Kubernetes Compliance |
| OPA/Gatekeeper | Policy Engine | Kubernetes, API-Gateways |

### Anwendungs-Compliance

| Tool | Beschreibung | Anwendungsbereich |
|------|--------------|-------------------|
| SonarQube | Code-Qualität und Security | Code-Compliance |
| OWASP Dependency-Check | Vulnerable Dependency Scanner | Supply Chain Security |
| Trivy | Container-Scanning | Container Security |
| Anchore | Container-Policy Engine | Container Compliance |
| Inspec | Compliance as Code Framework | Server Compliance |

### Compliance-Monitoring

| Tool | Beschreibung | Anwendungsbereich |
|------|--------------|-------------------|
| Falco | Runtime Security | Container Runtime |
| Prometheus/Alertmanager | Monitoring und Alerting | Metriken-basierte Compliance |
| AuditD/Wazuh | System Auditing | Host-basierte Compliance |
| AWS Config | Cloud Compliance | AWS Resources |
| Azure Policy | Cloud Compliance | Azure Resources |

## 📝 Framework-spezifische Automatisierung

### ISO 27001 Automatisierung

Beispielkonfiguration zur Automatisierung von ISO 27001-Kontrollen:

```yaml
# Beispiel: Chef InSpec-Profil für ISO 27001 A.12.4.1 (Event Logging)
control 'iso27001-a.12.4.1' do
  impact 0.7
  title 'Event logging'
  desc 'Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.'
  
  describe file('/etc/rsyslog.conf') do
    it { should exist }
    its('content') { should match /\*\.\* @logserver/ }
  end
  
  describe service('rsyslog') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
  
  describe command('ls -la /var/log/') do
    its('stdout') { should match /secure/ }
    its('stdout') { should match /auth\.log/ }
  end
end
```

### DSGVO/GDPR Automatisierung

Beispiel für automatisierte DSGVO-Compliance-Checks:

```python
# Python-Skript zur Prüfung auf unverschlüsselte PII-Daten
import re
import os

def scan_for_pii(directory):
    pii_patterns = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b'
    }
    
    findings = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.txt', '.json', '.csv', '.log')):
                try:
                    filepath = os.path.join(root, file)
                    with open(filepath, 'r') as f:
                        content = f.read()
                        for pii_type, pattern in pii_patterns.items():
                            matches = re.findall(pattern, content)
                            if matches:
                                findings.append({
                                    'file': filepath,
                                    'type': pii_type,
                                    'count': len(matches)
                                })
                except:
                    pass
    return findings

if __name__ == "__main__":
    findings = scan_for_pii('/path/to/scan')
    if findings:
        print("GDPR VIOLATION: Unencrypted PII found")
        for finding in findings:
            print(f"File: {finding['file']}, PII Type: {finding['type']}, Count: {finding['count']}")
        exit(1)
    else:
        print("No unencrypted PII found")
        exit(0)
```

## 📊 Compliance Dashboards und Reporting

Moderne Compliance-Dashboards ermöglichen die Visualisierung des Compliance-Status in Echtzeit:

### Prometheus/Grafana für Compliance-Metriken

```yaml
# Prometheus-Scrape-Konfiguration für Compliance-Metriken
scrape_configs:
  - job_name: 'compliance_exporter'
    static_configs:
      - targets: ['compliance-exporter:9090']
```

### Elastic Stack für Compliance-Monitoring

```yaml
# Logstash-Konfiguration für Compliance-Logs
input {
  beats {
    port => 5044
  }
}

filter {
  if [tags] == "compliance" {
    grok {
      match => { "message" => "%{GREEDYDATA:compliance_check}: %{WORD:result}" }
    }
  }
}

output {
  if [tags] == "compliance" {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "compliance-%{+YYYY.MM.dd}"
    }
  }
}
```

## 🔄 Kontinuierliche Verbesserung

Compliance Automation ist ein iterativer Prozess:

1. **Messen**: Compliance-Baseline erfassen
2. **Automatisieren**: Checks implementieren
3. **Testen**: Compliance validieren
4. **Verbessern**: Lücken schließen
5. **Wiederholen**: Kontinuierlich verbessern

> [!TIP]
> Beginne mit hochprioritären Compliance-Anforderungen und erweitere die Automatisierung schrittweise.

## Verwandte Themen
- [[600 Security/640 Compliance & Governance|Compliance & Governance]]
- [[600 Security/641 DSGVO|DSGVO/GDPR]]
- [[600 Security/642 ISO27001|ISO 27001]]
- [[400 CI_CD & Automation/000 CI_CD MOC|CI/CD & Automation]]
- [[300 Container & Orchestrierung/352 Kubernetes-Security|Kubernetes-Security]] 
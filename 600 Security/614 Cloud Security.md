---
tags: [security, cloud, aws, azure, gcp, ciso]
erstelldatum: 2025-04-28
aktualisiert: 2025-04-28
---

# Cloud Security

> [!INFO]
> Diese Dokumentation befasst sich mit Cloud-Sicherheitskonzepten und Best Practices für die Absicherung von Cloud-Umgebungen in AWS, Azure und GCP.

## 📋 Cloud Security-Grundlagen

### Shared Responsibility Model

Das Shared Responsibility Model definiert die Sicherheitsverantwortlichkeiten zwischen dem Cloud-Anbieter und dem Kunden:

```
┌─────────────────────────────────────────────────────────────┐
│                  Shared Responsibility Model                │
├───────────────────────────┬─────────────────────────────────┤
│    Cloud-Anbieter         │          Kunde                  │
├───────────────────────────┼─────────────────────────────────┤
│ • Physische Sicherheit    │ • Identitäts- und Zugriffsmanag.│
│ • Netzwerk-Infrastruktur  │ • Betriebssystemkonfiguration   │
│ • Virtualisierungs-Layer  │ • Anwendungssicherheit          │
│ • Service-Verfügbarkeit   │ • Daten-Verschlüsselung         │
│ • Host-Betriebssystem     │ • Netzwerkkonfiguration         │
└───────────────────────────┴─────────────────────────────────┘
```

### Cloud Security Risiken

- **Fehlkonfigurationen**: Die häufigste Ursache für Sicherheitsvorfälle
- **Identitäts- und Zugriffsmanagement**: Unzureichende Zugriffskontrollen
- **Daten-Exfiltration**: Unbefugter Datentransfer aus der Cloud
- **Geteilte Infrastruktur**: Risiken durch Multi-Tenant-Umgebungen
- **Mangelnde Transparenz**: Fehlende Einsicht in Cloud-Infrastruktur
- **Compliance-Herausforderungen**: Erfüllung von Compliance-Anforderungen in der Cloud

## 🔐 AWS Security

### IAM Best Practices

```bash
# AWS CLI - IAM-Benutzer überprüfen
aws iam list-users

# Benutzer ohne MFA identifizieren
aws iam list-users --query "Users[?MFADevices[0].EnableDate==null]"

# Root-Benutzeraktivität überprüfen
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root
```

**Best Practices:**
- Least-Privilege-Prinzip umsetzen mit IAM-Rollen und -Richtlinien
- Root-Benutzer sichern (MFA, minimale Verwendung)
- IAM-Rollen statt IAM-Benutzer für Anwendungen verwenden
- Regelmäßige Rotation von Zugriffsschlüsseln
- AWS Organizations für Multi-Account-Strategie nutzen
- Service Control Policies (SCPs) implementieren
- IAM Access Analyzer für Berechtigungsprüfungen einsetzen

### VPC-Sicherheit

```bash
# AWS CLI - Security Groups überprüfen
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?ToPort==22]]"

# Offen erreichbare Ressourcen identifizieren
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]"

# VPC Flow Logs aktivieren
aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-1a2b3c4d --traffic-type ALL --log-destination-type cloud-watch-logs --log-destination 'arn:aws:logs:region:account-id:log-group:flow-logs'
```

**Best Practices:**
- Network ACLs und Security Groups richtig konfigurieren
- VPC Flow Logs für Netzwerk-Monitoring aktivieren
- Private Subnets für sensible Workloads verwenden
- VPC-Endpoints für AWS-Services nutzen
- Transit Gateway für zentrale Netzwerkverwaltung
- PrivateLink für sichere Service-Verbindungen

### S3-Sicherheit

```bash
# AWS CLI - Öffentlich zugängliche S3-Buckets finden
aws s3api list-buckets --query "Buckets[].Name" | xargs -I {} aws s3api get-public-access-block --bucket {} --query "PublicAccessBlockConfiguration"

# S3-Bucket verschlüsseln
aws s3api put-bucket-encryption --bucket my-bucket --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

# S3-Bucket-Logging aktivieren
aws s3api put-bucket-logging --bucket source-bucket --bucket-logging-status '{"LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "logs/"}}'
```

**Best Practices:**
- S3 Block Public Access auf Account-Ebene aktivieren
- Bucket-Richtlinien mit Least-Privilege-Prinzip
- Serverseitige Verschlüsselung (SSE) für alle Buckets
- Versioning für kritische Buckets aktivieren
- S3-Zugriffsprotokollierung aktivieren
- Lebenszyklus-Richtlinien für Daten-Governance
- S3 Object Lock für kritische Daten (WORM)

### CloudTrail und Monitoring

```bash
# AWS CLI - CloudTrail-Status überprüfen
aws cloudtrail describe-trails

# Neuen Trail erstellen
aws cloudtrail create-trail --name secure-trail --s3-bucket-name my-cloudtrail-bucket --is-multi-region-trail --enable-log-file-validation

# Trail starten
aws cloudtrail start-logging --name secure-trail
```

**Best Practices:**
- Multi-Region-Trails aktivieren
- Log-Datei-Validierung aktivieren
- CloudTrail-Logs in dediziertem S3-Bucket mit Lebenszyklusrichtlinien
- CloudWatch Alarms für sicherheitsrelevante Ereignisse
- AWS Config für Konfigurationsänderungen
- GuardDuty für bedrohungsorientierte Erkennung
- AWS Security Hub für zentrales Sicherheitsmanagement

## 🔒 Azure Security

### Azure Active Directory

```powershell
# Azure CLI - Benutzer ohne MFA anzeigen
az ad user list --query "[?userType=='Member'].{DisplayName:displayName, UserPrincipalName:userPrincipalName, MFAStatus:strongAuthenticationDetail.methods[0].methodType}" -o table

# Berechtigungen für Anwendungen überprüfen
az ad app permission list --id <app-id> --query "[].resourceDisplayName"

# Konditionale Zugriffspolicy erstellen
az ad conditional-access policy create --name "Require MFA for all users" --state "enabledForReportingButNotEnforced" --conditions "{'users': {'includeUsers': ['all']}, 'applications': {'includeApplications': ['all']}}" --grant-controls "{'operator': 'OR', 'builtInControls': ['mfa']}" 
```

**Best Practices:**
- MFA für alle Benutzer erzwingen
- Azure AD Privileged Identity Management (PIM) für JIT-Zugriff
- Konditionale Zugriffsrichtlinien implementieren
- Azure AD Identity Protection aktivieren
- Regelmäßige Zugriffsüberprüfungen durchführen
- Passwortlose Authentifizierung wo möglich
- Azure AD Connect mit Pass-Through-Authentifizierung

### Azure Network Security

```powershell
# Azure CLI - NSG-Regeln überprüfen
az network nsg list --query "[].{NSGName:name, ResourceGroup:resourceGroup}" -o table

# Alle NSG-Regeln mit SSH-Zugriff anzeigen
az network nsg rule list --resource-group myRG --nsg-name myNSG --query "[?destinationPortRange=='22'].{Name:name, Access:access, Priority:priority}" -o table

# Azure Firewall einrichten
az network firewall create --name myFirewall --resource-group myRG --location westeurope
```

**Best Practices:**
- Azure Virtual Network mit Subnetzen
- Network Security Groups (NSGs) für Zugriffskontrollen
- Azure Firewall für zentralisierte Netzwerksicherheit
- Azure DDoS Protection für kritische Ressourcen
- Private Link für Service-Zugriff
- Azure Bastion für sichere VM-Verwaltung
- Network Watcher für Netzwerkdiagnostik

### Azure Storage-Sicherheit

```powershell
# Azure CLI - Storage Accounts mit öffentlichem Zugriff überprüfen
az storage account list --query "[?allowBlobPublicAccess == true].{Name:name, ResourceGroup:resourceGroup}" -o table

# HTTPS erzwingen
az storage account update --name mystorageaccount --resource-group myRG --https-only true

# Verschlüsselung aktivieren
az storage account update --name mystorageaccount --resource-group myRG --encryption-services blob file
```

**Best Practices:**
- Öffentlichen Zugriff deaktivieren
- Azure Storage Service Encryption (SSE) verwenden
- SAS-Token mit kurzer Gültigkeit nutzen
- Storage Firewall konfigurieren (IP- und VNET-basierte Zugriffskontrolle)
- Azure Private Endpoint für Storage-Zugriff
- Storage Analytics-Protokollierung aktivieren
- Immutable Storage für kritische Daten

### Azure Security Center und Monitoring

```powershell
# Azure CLI - Security Center-Status überprüfen
az security center subscription show

# Security Center-Empfehlungen anzeigen
az security assessment list --query "[].{AssessmentName:displayName, ResourceName:resourceDetails.name, Status:status.code}" -o table

# Log Analytics Workspace für Security Center konfigurieren
az security auto-provisioning-setting update --name default --auto-provision On --workspace /subscriptions/<subscription-id>/resourceGroups/<rg-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>
```

**Best Practices:**
- Microsoft Defender for Cloud aktivieren (ehemals Security Center)
- Log Analytics Workspace für zentrale Protokollierung
- Automatische Bereitstellung des Monitoring Agents
- Azure Monitor Alerts für sicherheitsrelevante Ereignisse
- Azure Sentinel für SIEM und SOAR-Funktionen
- Azure Activity Log für Audit-Zwecke
- Compliance-Management-Tools nutzen

## 🔐 GCP Security

### IAM und Identitätsmanagement

```bash
# gcloud CLI - Dienstkonten auflisten
gcloud iam service-accounts list

# IAM-Bindungen prüfen
gcloud projects get-iam-policy PROJECT_ID --format=json

# Berechtigungen eines Dienstkontos anzeigen
gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" --filter="bindings.members:serviceAccount:SERVICE_ACCOUNT_EMAIL" --format="table(bindings.role)"
```

**Best Practices:**
- Organisationsweites IAM-Konzept mit Ressourcenhierarchie
- Dienstkonten mit minimalen Berechtigungen
- Google Cloud Identity für SSO
- 2FA/MFA für alle Benutzer
- IAM-Bedingungen für kontextabhängige Zugriffssteuerung
- Vorübergehende Identitätstoken statt langlebige Credentials
- IAM Recommender für Berechtigungsprüfungen nutzen

### VPC-Sicherheit

```bash
# gcloud CLI - Firewall-Regeln prüfen
gcloud compute firewall-rules list

# Offene SSH-Ports identifizieren
gcloud compute firewall-rules list --filter="allowed.ports:22"

# VPC Flow Logs aktivieren
gcloud compute networks subnets update SUBNET_NAME --region=REGION --enable-flow-logs
```

**Best Practices:**
- VPC Service Controls für Ressourcenisolierung
- Private Google Access für API-Zugriff
- Hierarchische Firewall-Richtlinien
- VPC Flow Logs für Netzwerk-Monitoring
- Cloud NAT für Outbound-Verbindungen
- Cloud Interconnect oder VPN für sichere Hybridverbindungen
- Dedicated Interconnect für kritische Workloads

### GCS-Sicherheit (Google Cloud Storage)

```bash
# gcloud CLI - Öffentliche Buckets identifizieren
gcloud storage buckets list --format="table(name)" | tail -n +2 | while read bucket; do
  echo -n "$bucket: "
  gsutil iam get gs://$bucket | grep allUsers || echo "not public"
done

# CMEK-Verschlüsselung aktivieren
gcloud storage buckets update gs://my-bucket --default-encryption-key=projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY
```

**Best Practices:**
- IAM für Bucket-Zugriffskontrolle
- Öffentlichen Zugriff vermeiden
- Default-ACLs für neue Objekte konfigurieren
- Standardverschlüsselung mit CMEK (Customer-Managed Encryption Keys)
- Object Lifecycle Management für Datenhaltung
- Object Versioning für kritische Daten
- Object Hold und Retention für Compliance

### Cloud Logging und Monitoring

```bash
# gcloud CLI - Log-Sinks prüfen
gcloud logging sinks list

# Audit-Logs exportieren
gcloud logging sinks create security-audit-sink storage.googleapis.com/my-audit-logs --log-filter='logName:"cloudaudit.googleapis.com"'

# Cloud Monitoring erstellen
gcloud alpha monitoring policies create --policy-from-file=policy.json
```

**Best Practices:**
- Cloud Audit Logs für alle Dienste aktivieren
- Data Access Logs für sensible Daten
- Log-Export in langfristigen Speicher (GCS)
- Security Command Center aktivieren
- Event Threat Detection einschalten
- Cloud Monitoring mit Sicherheits-Dashboards
- Security Health Analytics für Schwachstellen

## 🔄 Multi-Cloud Security

### Identity Federation

```bash
# AWS CLI - SAML-Provider für SSO einrichten
aws iam create-saml-provider --saml-metadata-document file://metadata.xml --name MySAMLProvider

# Azure CLI - Enterprise App für SAML einrichten
az ad app create --display-name "My Enterprise App"

# GCP CLI - Workspace für SSO konfigurieren
gcloud organizations add-iam-policy-binding ORGANIZATION_ID --member=group:GROUP_EMAIL --role=roles/resourcemanager.organizationAdmin
```

**Best Practices:**
- Zentrales Identity Provider (IdP) wie Azure AD oder Okta
- SAML/OIDC für föderierte Identitäten
- Einheitliche MFA-Richtlinien über alle Cloud-Anbieter
- Zentralisiertes Lifecycle-Management
- Rollenbasierte Zugriffskontrollen anbieterübergreifend
- SSO für vereinfachte Benutzererfahrung

### Sicherheitsüberwachung

```bash
# Terraform - Cloud-übergreifendes Logging
resource "aws_cloudtrail" "centralised_logging" {
  name                          = "centralised-logging"
  s3_bucket_name                = aws_s3_bucket.logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

resource "google_logging_project_sink" "centralised_logging" {
  name        = "centralised-logging"
  description = "Central log export to Cloud Storage"
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
}
```

**Best Practices:**
- SIEM-Lösung für Cloud-übergreifendes Monitoring (Splunk, ELK)
- Zentralisierte Log-Aggregation
- Cloud-übergreifende Sicherheitsrichtlinien
- Automatisierte Reaktionen auf Sicherheitsereignisse
- Regelmäßige Compliance-Audits über alle Cloud-Anbieter
- Cloud Security Posture Management (CSPM)
- Threat Intelligence-Integration

### Data Protection

```bash
# AWS CLI - S3-Bucket mit KMS-Verschlüsselung
aws s3api create-bucket --bucket my-secure-bucket --region eu-central-1
aws s3api put-bucket-encryption --bucket my-secure-bucket --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "KEY-ARN"}}]}'

# Azure CLI - Verschlüsselten Storage Account erstellen
az storage account create --name mysecurestorage --resource-group myRG --location westeurope --sku Standard_LRS --encryption-services blob file

# GCP CLI - GCS-Bucket mit CMEK
gsutil mb -l eu gs://my-secure-bucket
gsutil kms encryption -k projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY gs://my-secure-bucket
```

**Best Practices:**
- Einheitliche Verschlüsselungsstrategie
- Cloud-unabhängiges Key Management (HSM)
- Data Classification und Schutz nach Vertraulichkeit
- Datensicherung und Recovery-Strategien
- Datenmigrationssicherheit
- Cloud Data Loss Prevention (DLP)
- Dateizugriff überwachen und protokollieren

### Compliance-Framework

```yaml
# Terraform - Compliance-as-Code-Beispiel
module "aws_compliance" {
  source = "./modules/aws-compliance"
  enable_cloudtrail = true
  enable_config = true
  enable_guardduty = true
  s3_encryption = true
}

module "azure_compliance" {
  source = "./modules/azure-compliance"
  enable_defender = true
  enable_activity_logs = true
  storage_encryption = true
}

module "gcp_compliance" {
  source = "./modules/gcp-compliance"
  enable_security_center = true
  enable_audit_logs = true
  bucket_encryption = true
}
```

**Best Practices:**
- Zentralisiertes Compliance-Management
- Cloud-übergreifende Compliance-Automatisierung
- Regelmäßige Vulnerability Assessments
- Penetrationstests in allen Cloud-Umgebungen
- Automatisierte Compliance-Berichte
- Third-Party-Audits
- Kontinuierliche Compliance-Überwachung

## 📚 Cloud-Security-Frameworks und -Standards

- **CIS Benchmarks**: Spezifische Sicherheitsempfehlungen für AWS, Azure und GCP
- **Cloud Security Alliance (CSA)**: Cloud Controls Matrix (CCM)
- **NIST SP 800-53**: Sicherheitskontrollen für Cloud-Umgebungen
- **ENISA Cloud Security Guide**: Europäisches Framework
- **ISO/IEC 27017**: Informationssicherheitskontrollen für Cloud-Services
- **ISO/IEC 27018**: Datenschutzkontrollen für Cloud-Services
- **SOC 2**: Trust Service Criteria für Cloud-Services

## 🔄 DevSecOps für Cloud-Umgebungen

### Infrastructure as Code (IaC) Security

```hcl
# Terraform - Secure S3 Bucket
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  versioning {
    enabled = true
  }
  
  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
  
  lifecycle_rule {
    enabled = true
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}
```

**Best Practices:**
- IaC-Sicherheitsscans mit Tools wie Checkov, tfsec
- GitOps für Infrastruktur-Änderungsmanagement
- Immutable Infrastructure-Prinzipien
- Versionskontrolle für IaC-Code
- CI/CD-Pipelines mit Sicherheitsgates
- Terraform Module für vorkonfigurierte, sichere Komponenten
- Infrastructure Drift Detection

### Container-Sicherheit

```yaml
# Kubernetes-Sicherheitskontext
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      readOnlyRootFilesystem: true
```

**Best Practices:**
- Container-Image-Scanning (Trivy, Clair)
- Pod Security Standards/Policies
- Network Policies für Mikrosegmentierung
- Service Mesh für Zero-Trust-Netzwerke
- Admission Controllers (OPA/Gatekeeper)
- Container Runtime Security (Falco, Aqua)
- Image Signieren und Verifizieren

## Verwandte Themen
- [[600 Security/642 ISO27001|ISO 27001]]
- [[600 Security/641 DSGVO|DSGVO/GDPR]]
- [[600 Security/643 Compliance Automation|Compliance Automation]]
- [[600 Security/602 Identity & Access Management|IAM]]
- [[100 Infrastruktur/130 AWS|AWS]]
- [[100 Infrastruktur/131 Azure|Azure]] 
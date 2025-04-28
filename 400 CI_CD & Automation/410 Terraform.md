# Terraform

Tags: #tool #iac #automation

## Überblick
Terraform ist ein Open-Source-Tool für Infrastructure as Code (IaC), das die Erstellung, Änderung und Versionierung von Infrastruktur sicher und effizient ermöglicht. Es unterstützt zahlreiche Infrastrukturanbieter wie AWS, Azure, GCP und mehr.

## Installationsschritte
```bash
# Installation auf Ubuntu
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install terraform

# Überprüfen der Installation
terraform version
```

## Grundlegende Konfiguration
```hcl
# Beispiel-Konfiguration für AWS
provider "aws" {
  region = "eu-central-1"
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  tags = {
    Name = "terraform-example"
  }
}

# Verwenden von Variablen
variable "instance_name" {
  description = "Name des EC2-Instances"
  type        = string
  default     = "example-instance"
}

output "instance_ip" {
  value = aws_instance.example.public_ip
}
```

## Wichtige Befehle
```bash
terraform init           # Initialisiert ein Terraform-Arbeitsverzeichnis
terraform plan           # Erstellt einen Ausführungsplan
terraform apply          # Wendet Änderungen an
terraform destroy        # Zerstört erstellte Ressourcen
terraform validate       # Überprüft Konfigurationen
terraform fmt            # Formatiert Konfigurationsdateien
terraform state list     # Zeigt Ressourcen im State
terraform import [addr] [ID] # Importiert existierende Infrastruktur
```

## Best Practices
- Remote State in S3/Azure Blob/etc. speichern
- State-Locking verwenden (z.B. mit DynamoDB)
- Modulare Struktur erstellen
- Terraform-Versionen festlegen (mit `required_version`)
- Workspace für verschiedene Umgebungen nutzen
- Variablen für wiederverwendbare Konfigurationen einsetzen
- Outputs für wichtige Informationen definieren
- CI/CD-Pipeline für Terraform-Ausführung verwenden

## Häufige Probleme und Lösungen
- **State-Konflikte**: Remote State mit Locking verwenden
- **Änderungen außerhalb von Terraform**: Regelmäßig `terraform import` nutzen
- **Langsame Pläne**: Größe der Infrastruktur reduzieren, in Module aufteilen
- **Fehlerbehandlung**: `depends_on` für Abhängigkeiten, `lifecycle`-Blocks

## Sicherheitshinweise
- Secrets nicht in Terraform-Code speichern
- IAM-Rollen/Berechtigungen für Terraform-Ausführung einschränken
- Sensible Daten im State mit `sensitive = true` markieren
- Remote State verschlüsseln
- Terraform Cloud/Enterprise RBAC für Team-Umgebungen

## Monitoring & Logging
- Terraform-Ausführungen in CI/CD-Pipeline protokollieren
- Cost Estimation für Ressourcen nutzen
- Sentinel Policies für Compliance
- Terraform Cloud/Enterprise für Audit-Logs

## Nützliche Links
- [Terraform-Dokumentation](https://www.terraform.io/docs/index.html)
- [Terraform Registry](https://registry.terraform.io/)
- [Terraform Best Practices](https://www.terraform-best-practices.com/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

## Verwandte Themen
- [[400 CI_CD & Automation/411 AWS CloudFormation|CloudFormation]]
- [[100 Infrastruktur/140 Terraform|Terraform-Module]]
- [[100 Infrastruktur/130 AWS|AWS]]
- [[100 Infrastruktur/131 Azure|Azure]] 
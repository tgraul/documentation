# Ansible

Tags: #tool #automation #configuration-management

## Überblick
Ansible ist ein Open-Source-Tool für Automatisierung, Konfigurationsmanagement und Anwendungsbereitstellung. Es verwendet eine einfache YAML-Syntax und benötigt keine Agenten auf den Zielservern, da es SSH für die Kommunikation nutzt.

## Installationsschritte
```bash
# Installation auf Ubuntu/Debian
sudo apt update
sudo apt install ansible

# Installation auf RHEL/CentOS
sudo dnf install epel-release
sudo dnf install ansible

# Installation mit pip
python3 -m pip install --user ansible

# Version prüfen
ansible --version
```

## Grundlegende Konfiguration
### Inventory-Datei (hosts)
```ini
# /etc/ansible/hosts oder lokale inventory-Datei
[webservers]
web1.example.com
web2.example.com

[dbservers]
db1.example.com
db2.example.com

[all:vars]
ansible_user=admin
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

### Ansible Configuration (ansible.cfg)
```ini
[defaults]
inventory = ./inventory
remote_user = admin
private_key_file = ~/.ssh/id_rsa
host_key_checking = False
```

### Beispiel-Playbook (playbook.yml)
```yaml
---
- name: Webserver einrichten
  hosts: webservers
  become: yes
  
  tasks:
    - name: Nginx installieren
      apt:
        name: nginx
        state: present
        update_cache: yes
      
    - name: Nginx starten und aktivieren
      service:
        name: nginx
        state: started
        enabled: yes
        
    - name: Konfigurationsdatei kopieren
      template:
        src: templates/nginx.conf.j2
        dest: /etc/nginx/nginx.conf
      notify:
        - Nginx neustarten
        
  handlers:
    - name: Nginx neustarten
      service:
        name: nginx
        state: restarted
```

## Wichtige Befehle
```bash
# Ping-Test (Verbindungstest zu allen Hosts)
ansible all -m ping

# Ad-hoc Befehl ausführen
ansible webservers -m shell -a "uptime"

# Playbook ausführen
ansible-playbook playbook.yml

# Playbook mit Inventardatei ausführen
ansible-playbook -i inventory playbook.yml

# Playbook mit bestimmten Hosts ausführen
ansible-playbook playbook.yml --limit web1.example.com

# Playbook mit Tags ausführen
ansible-playbook playbook.yml --tags "configuration,packages"

# Syntax-Check für Playbook
ansible-playbook playbook.yml --syntax-check

# Dry Run (--check und --diff)
ansible-playbook playbook.yml --check --diff
```

## Best Practices
- Verwende Rollen für wiederverwendbare Konfigurationen
- Gruppiere Variablen in `group_vars` und `host_vars`
- Strukturiere Playbooks in separate Dateien und Tasks
- Nutze Tags für selektive Ausführung
- Verwende Jinja2-Templates für Konfigurationsdateien
- Speichere sensitive Informationen in Ansible Vault
- Halte Playbooks idempotent (mehrfache Ausführung ändert nichts)
- Dokumentiere Rollen und Playbooks

## Häufige Probleme und Lösungen
- **SSH-Verbindungsprobleme**: Key-Permissions, SSH-Agent oder `--ask-pass`
- **Berechtigungsprobleme**: `become: yes` verwenden oder `--ask-become-pass`
- **Idempotenz-Probleme**: `creates`, `removes` oder `changed_when` nutzen
- **Leistungsprobleme bei vielen Hosts**: Parallele Ausführung mit `forks` erhöhen
- **Debug-Informationen**: `-v`, `-vv` oder `-vvv` für verbesserte Ausgabe

## Sicherheitshinweise
- Sensible Daten mit Ansible Vault verschlüsseln
- SSH-Keys regelmäßig rotieren
- Berechtigungen für spezifische Hosts/Gruppen einschränken
- Vault-Passwörter sicher aufbewahren
- Playbooks und Inventare in Versionskontrolle speichern, aber keine Secrets

## Monitoring & Logging
- Ansible-Tower/AWX für Web-UI und Jobplanung
- Playbook-Ausführungen protokollieren (z.B. mit `log_path`)
- Callbacks für benutzerdefinierte Protokollierung nutzen
- Fehlgeschlagene Tasks überwachen und Benachrichtigungen einrichten

## Nützliche Links
- [Ansible-Dokumentation](https://docs.ansible.com/)
- [Ansible Galaxy](https://galaxy.ansible.com/) (Community-Rollen)
- [Ansible Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- [Jinja2-Templating](https://jinja.palletsprojects.com/en/3.0.x/templates/)

## Verwandte Themen
- [[800 Tooling/811 Puppet|Puppet]]
- [[400 CI_CD & Automation/000 CI_CD MOC|CI/CD & Automation]]
- [[600 Security/652 Secret Management|Secret Management (Ansible Vault)]]
- [[200 Betriebssysteme/210 Linux Basics|Linux Basics]] 
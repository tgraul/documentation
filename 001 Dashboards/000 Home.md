# 🏠 Home Dashboard

> [!note] Willkommen in deiner DevOps-Wissensdatenbank
> Hier findest du alle wichtigen Informationen, Anleitungen und Ressourcen zu DevOps und Systemadministration.

## Schnellzugriff
- [[100 Infrastruktur/000 Infrastruktur MOC|🖥️ Infrastruktur]]
- [[200 Betriebssysteme/000 Betriebssysteme MOC|💻 Betriebssysteme]]
- [[300 Container & Orchestrierung/000 Container MOC|🐳 Container & Orchestrierung]]
- [[400 CI_CD & Automation/000 CI_CD MOC|🔄 CI/CD & Automation]]
- [[500 Monitoring & Logging/000 Monitoring MOC|📊 Monitoring & Logging]]
- [[600 Security/000 Security MOC|🔒 Security]]
- [[700 Datenbanken/000 Datenbanken MOC|💾 Datenbanken]]
- [[800 Tooling/000 Tooling MOC|🧰 Tooling]]
- [[950 Praxis-Projekte/000 Projekte MOC|🚀 Projekte]]

## 📅 Kalender
```dataviewjs
// Kalender-Integration mit dem calendar-Plugin
const calendarData = {
  year: new Date().getFullYear(),
  month: new Date().getMonth(),
  holidays: [],
  entries: [],
};

dv.calendar(calendarData);
```

## Aktuelle Projekte
```dataview
TABLE file.ctime as "Erstellt", file.mtime as "Aktualisiert"
FROM "950 Praxis-Projekte"
WHERE contains(tags, "project") AND !contains(file.name, "MOC")
SORT file.mtime DESC
LIMIT 5
```

## Kürzlich aktualisierte Dokumente
```dataview
TABLE file.mtime as "Aktualisiert", tags
FROM "100 Infrastruktur" OR "200 Betriebssysteme" OR "300 Container & Orchestrierung" OR "400 CI_CD & Automation" OR "500 Monitoring & Logging" OR "600 Security" OR "700 Datenbanken" OR "800 Tooling"
SORT file.mtime DESC
LIMIT 8
```

## 📝 Dokumentenstatistik
```dataview
TABLE length(rows) as "Anzahl Dokumente"
FROM -"900 Referenzen" AND -"000 Inbox" AND -"001 Dashboards" AND -"850 Skripte"
GROUP BY SUBSTRING(file.folder, 0, 3) as "Bereich"
SORT Bereich ASC
```

## Offene Aufgaben
```dataview
TASK
FROM "000 Inbox" OR "950 Praxis-Projekte"
WHERE !completed
LIMIT 10
```

## Häufig genutzte Tools
- [[800 Tooling/810 Ansible|Ansible]] - Konfigurationsmanagement
- [[300 Container & Orchestrierung/310 Kubernetes|Kubernetes]] - Container-Orchestrierung
- [[400 CI_CD & Automation/410 Terraform|Terraform]] - Infrastructure as Code
- [[300 Container & Orchestrierung/300 Docker|Docker]] - Container
- [[600 Security/660 fail2ban|fail2ban]] - Intrusion Prevention

## Nützliche Ressourcen
- [Linux-Dokumentation](https://www.kernel.org/doc/html/latest/)
- [Kubernetes-Dokumentation](https://kubernetes.io/docs/home/)
- [Docker-Dokumentation](https://docs.docker.com/)
- [AWS-Dokumentation](https://docs.aws.amazon.com/)
- [Terraform-Dokumentation](https://developer.hashicorp.com/terraform/docs)

## Checklisten & Templates
- [[900 Referenzen/Checklisten/Server Hardening|Server-Hardening-Checkliste]]
- [[900 Referenzen/Checklisten/Kubernetes Deployment|Kubernetes-Deployment-Checkliste]]
- [[900 Referenzen/Vorlagen/Technologie-Dokumentation|Technologie-Dokumentation]]
- [[900 Referenzen/Vorlagen/Projekt-Dokumentation|Projekt-Dokumentation]]

> [!tip] Tipp zur Nutzung
> Nutze `Ctrl+E` oder die QuickAdd-Befehle, um schnell neue Einträge zu erstellen. 
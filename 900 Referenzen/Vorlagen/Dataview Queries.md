---
tags: [dataview, query, template]
erstelldatum: <% tp.date.now("YYYY-MM-DD") %>
aktualisiert: <% tp.date.now("YYYY-MM-DD") %>
---

# Nützliche Dataview-Abfragen

Diese Sammlung enthält hilfreiche Dataview-Abfragen, die du in deiner Dokumentation verwenden kannst.

> [!tip] Verwendung
> Kopiere die Abfragen und füge sie in deine Dokumentationsseiten ein, um dynamische Inhalte zu generieren.

## Projektübersichten

### Alle aktiven Projekte anzeigen

```dataview
TABLE
  file.ctime as "Erstellt",
  file.mtime as "Aktualisiert"
FROM "950 Praxis-Projekte"
WHERE contains(tags, "active") AND !contains(file.name, "MOC")
SORT file.mtime DESC
```

### Projektstatus-Dashboard

```dataview
TABLE
  choice(contains(tags, "active"), "✅", "❌") as "Aktiv",
  choice(contains(tags, "completed"), "✅", "❌") as "Abgeschlossen",
  choice(contains(tags, "blocked"), "❌", "✅") as "Blockiert"
FROM "950 Praxis-Projekte"
WHERE !contains(file.name, "MOC") AND !contains(file.name, "Kanban")
SORT file.name ASC
```

## Dokumenten-Management

### Kürzlich aktualisierte Dokumente nach Bereich

```dataview
TABLE
  file.folder as "Ordner",
  file.mtime as "Aktualisiert"
FROM -"900 Referenzen" AND -"000 Inbox" AND -"001 Dashboards"
SORT file.mtime DESC
LIMIT 10
```

### Dokumente ohne Tags

```dataview
TABLE
  file.folder as "Ordner",
  file.ctime as "Erstellt"
FROM -"900 Referenzen" AND -"000 Inbox" AND -"001 Dashboards"
WHERE length(file.tags) = 0
SORT file.folder ASC
```

## Aufgabenverwaltung

### Offene Aufgaben nach Fälligkeit

```dataview
TASK
FROM "950 Praxis-Projekte" OR "000 Inbox"
WHERE !completed AND contains(text, "due:")
SORT file.mtime DESC
```

### Aufgaben pro Bereich

```dataviewjs
// Gruppiere Aufgaben nach Bereich
const pages = dv.pages('-"900 Referenzen" AND -"001 Dashboards"');
const tasks = pages.file.tasks;
const areas = {};

// Zähle Aufgaben pro Bereich
for (const page of pages) {
  const area = page.file.folder.split('/')[0];
  if (!areas[area]) areas[area] = { total: 0, completed: 0 };
  
  const pageTasks = page.file.tasks;
  areas[area].total += pageTasks.length;
  areas[area].completed += pageTasks.where(t => t.completed).length;
}

// Erstelle Tabelle
dv.table(
  ["Bereich", "Offen", "Erledigt", "Gesamt", "Fortschritt"],
  Object.entries(areas)
    .filter(([area, counts]) => counts.total > 0)
    .map(([area, counts]) => [
      area, 
      counts.total - counts.completed,
      counts.completed,
      counts.total,
      Math.round((counts.completed / counts.total) * 100) + "%"
    ])
    .sort((a, b) => a[0].localeCompare(b[0]))
);
```

## Technologie-Tracking

### Verwendete Technologien

```dataview
TABLE
  file.ctime as "Erstellt",
  file.mtime as "Aktualisiert"
FROM "800 Tooling" OR "300 Container & Orchestrierung"
WHERE contains(tags, "tool")
SORT file.name ASC
```

### Technologien nach Kategorie

```dataview
TABLE rows.file.link as "Technologien"
FROM "800 Tooling" OR "300 Container & Orchestrierung" OR "400 CI_CD & Automation"
WHERE contains(tags, "tool")
GROUP BY choice(contains(tags, "monitoring"), "Monitoring",
         choice(contains(tags, "container"), "Container",
         choice(contains(tags, "automation"), "Automation",
         choice(contains(tags, "database"), "Datenbank", "Sonstige")))) as Kategorie
SORT Kategorie ASC
```

## Sicherheits-Tracking

### Sicherheitsrelevante Dokumente

```dataview
TABLE
  file.mtime as "Aktualisiert",
  choice(contains(tags, "critical"), "✅", "❌") as "Kritisch"
FROM "600 Security"
WHERE contains(tags, "security")
SORT file.mtime DESC
```

## Fortschritts-Tracking

### Checklisten-Fortschritt

```dataviewjs
// Fortschritt aller Checklisten anzeigen
const checklists = dv.pages('"900 Referenzen/Checklisten"');

// Tabelle mit Fortschrittsbalken
dv.table(
  ["Checkliste", "Fortschritt", "Status"],
  checklists.map(page => {
    const tasks = page.file.tasks;
    const total = tasks.length;
    const completed = tasks.where(t => t.completed).length;
    const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;
    
    // Erstelle Fortschrittsbalken
    const progressBar = "▓".repeat(Math.floor(percentage/10)) + "░".repeat(10 - Math.floor(percentage/10));
    
    return [
      page.file.link,
      `${progressBar} ${percentage}% (${completed}/${total})`,
      percentage === 100 ? "✅ Abgeschlossen" : "🔄 In Arbeit"
    ];
  })
);
```

## Eigene Abfragen

Hier können eigene, spezifische Dataview-Abfragen hinzugefügt werden, die für die Dokumentation nützlich sind. 
---
tags: [template, quickadd]
erstelldatum: <% tp.date.now("YYYY-MM-DD") %>
aktualisiert: <% tp.date.now("YYYY-MM-DD") %>
---

# QuickAdd Vorlagen

Diese Vorlagen sind für die Nutzung mit dem QuickAdd-Plugin konfiguriert.

> [!tip] QuickAdd verwenden
> Drücke `Strg+P` und suche nach "QuickAdd", um schnell neue Einträge nach diesen Vorlagen zu erstellen.

## Technologie-Dokumentation

```js
// QuickAdd Template für Technologie-Dokumentation
module.exports = {
    entry: "900 Referenzen/Vorlagen/Technologie-Dokumentation",
    folder: () => {
        // Zeige ein Auswahlmenü mit Ordnern
        const folders = [
            "300 Container & Orchestrierung",
            "400 CI_CD & Automation",
            "800 Tooling"
        ];
        
        // Wähle einen Ordner aus dem Array
        return QuickAdd.quickAddApi.suggester(
            folders, 
            folders
        );
    },
    fileNameFormat: {
        format: "{{VALUE}}",
        enabled: true,
    },
    open: true,
}
```

## Projektverwaltung

```js
// QuickAdd Template für Projekte
module.exports = {
    entry: "900 Referenzen/Vorlagen/Projekt-Dokumentation",
    folder: "950 Praxis-Projekte",
    fileNameFormat: {
        format: "{{DATE:YYYMMDDHHmm}} {{VALUE}}",
        enabled: true,
    },
    open: true,
}
```

## Problemlösungsdokumentation

```js
// QuickAdd Template für Troubleshooting
module.exports = {
    entry: async (params) => {
        // Template-Text
        const template = `---
tags: [troubleshooting, ${await params.variables.problemTyp}]
erstelldatum: ${params.app.plugins.plugins.templater.templater.functions.date_functions.now("YYYY-MM-DD")}
aktualisiert: ${params.app.plugins.plugins.templater.templater.functions.date_functions.now("YYYY-MM-DD")}
---

# ${params.variables.title}

> [!warning] Problem
> ${params.variables.problemBeschreibung}

## Symptome
- ${params.variables.symptom1}
- ${params.variables.symptom2}

## Fehlerbehebung
1. ${params.variables.loesung1}
2. ${params.variables.loesung2}

## Lösung
${params.variables.finaleLoesungsbeschreibung}

## Vermeidung
${params.variables.vermeidung}

---

Zuletzt aktualisiert: ${params.app.plugins.plugins.templater.templater.functions.date_functions.now("YYYY-MM-DD")}`;

        return template;
    },
    folder: "900 Referenzen/Problemlösungen",
    fileNameFormat: {
        format: "{{VALUE}} Lösung",
        enabled: true,
    },
    open: true,
}
```

## Diagramm-Erstellung

```js
// QuickAdd Template für Excalidraw-Diagramme
module.exports = {
    entry: "900 Referenzen/Vorlagen/Excalidraw Diagramm",
    folder: folder => {
        // Je nach Typ des Diagramms in unterschiedlichen Ordner speichern
        const folderMap = {
            "Infrastruktur": "100 Infrastruktur/150 Diagramme",
            "Kubernetes": "300 Container & Orchestrierung/350 Diagramme",
            "CI/CD": "400 CI_CD & Automation/450 Diagramme",
            "Architektur": "950 Praxis-Projekte/Diagramme"
        };
        
        return QuickAdd.quickAddApi.suggester(
            Object.keys(folderMap),
            Object.values(folderMap)
        );
    },
    fileNameFormat: {
        format: "{{VALUE}} Diagramm",
        enabled: true,
    },
    open: true,
}
```

## Eigene Anpassungen

> [!note] Anpassungshinweise
> Diese Vorlagen können als Ausgangspunkt für deine eigenen QuickAdd-Konfigurationen dienen. Passe sie nach Bedarf an deine Arbeitsabläufe an. 
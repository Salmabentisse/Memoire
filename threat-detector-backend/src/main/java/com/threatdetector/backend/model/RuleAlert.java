package com.threatdetector.backend.model;

/**
 * Représente une alerte générée par le moteur de règles classique.
 * Chaque alerte correspond à une règle déclenchée sur une ligne du CSV.
 * Jackson sérialise automatiquement les getters en JSON pour le frontend.
 */
public class RuleAlert {

    private int row;           // numéro de la ligne dans le CSV (commence à 1)
    private String rule;       // identifiant de la règle (ex: "PORT_SCAN_DETECTED")
    private String severity;   // niveau de gravité : LOW, MEDIUM ou HIGH
    private String description; // message descriptif avec les détails du flux réseau

    // Constructeur vide requis par Jackson pour la désérialisation
    public RuleAlert() {}

    // Constructeur utilisé par le RuleEngineService pour créer les alertes
    public RuleAlert(int row, String rule, String severity, String description) {
        this.row = row;
        this.rule = rule;
        this.severity = severity;
        this.description = description;
    }

    // Getters — Spring Jackson les utilise pour convertir l'objet en JSON
    public int getRow() { return row; }
    public String getRule() { return rule; }
    public String getSeverity() { return severity; }
    public String getDescription() { return description; }
}

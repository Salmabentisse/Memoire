package com.threatdetector.backend.model;

import java.util.List;

/**
 * Résultat complet de l'analyse d'un fichier CSV.
 * Cet objet est retourné par le backend en JSON au frontend Angular.
 * Il contient les alertes des deux approches (règles et IA) et les métriques de comparaison.
 */
public class CompareResult {

    private List<RuleAlert> ruleAlerts;  // alertes détectées par le moteur de règles classique
    private List<LlmAlert> llmAlerts;    // alertes détectées par l'IA Gemini
    private CompareMetrics metrics;      // métriques de performance des deux approches

    // Constructeur vide requis par Jackson pour la sérialisation JSON
    public CompareResult() {}

    // Constructeur utilisé par AnalysisService une fois l'analyse terminée
    public CompareResult(List<RuleAlert> ruleAlerts, List<LlmAlert> llmAlerts, CompareMetrics metrics) {
        this.ruleAlerts = ruleAlerts;
        this.llmAlerts = llmAlerts;
        this.metrics = metrics;
    }

    // Getters — Spring Jackson les utilise pour convertir l'objet en JSON
    public List<RuleAlert> getRuleAlerts()   { return ruleAlerts; }
    public List<LlmAlert> getLlmAlerts()     { return llmAlerts; }
    public CompareMetrics getMetrics()       { return metrics; }
}

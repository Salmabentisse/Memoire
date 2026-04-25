package com.threatdetector.backend.model;

/**
 * Métriques affichées dans le tableau de bord après l'analyse.
 * On garde uniquement ce qui est utile pour le frontend.
 */
public class CompareMetrics {

    private int totalRows;           // nombre total de lignes analysées dans le CSV
    private double llmAvgConfidence; // score de confiance moyen des alertes IA (0-100)

    // Constructeur vide requis par Jackson pour la sérialisation JSON
    public CompareMetrics() {}

    public CompareMetrics(int totalRows, double llmAvgConfidence) {
        this.totalRows = totalRows;
        this.llmAvgConfidence = llmAvgConfidence;
    }

    public int getTotalRows()           { return totalRows; }
    public double getLlmAvgConfidence() { return llmAvgConfidence; }
}

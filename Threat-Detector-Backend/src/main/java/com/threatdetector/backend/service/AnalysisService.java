package com.threatdetector.backend.service;

import com.threatdetector.backend.model.*;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;


/**
 * Service principal qui orchestre toute l'analyse d'un fichier CSV.
 * Il appelle les autres services dans l'ordre : parsing → règles → IA → métriques.
 */
@Service
public class AnalysisService {

    // Injection des services nécessaires via le constructeur
    private final CsvParserService csvParser;
    private final RuleEngineService ruleEngine;
    private final LlmService llmService;

    public AnalysisService(CsvParserService csvParser,
                           RuleEngineService ruleEngine,
                           LlmService llmService) {
        this.csvParser = csvParser;
        this.ruleEngine = ruleEngine;
        this.llmService = llmService;
    }

    /**
     * Lance l'analyse complète du fichier CSV uploadé.
     *
     * @param file fichier CSV uploadé par l'utilisateur
     * @return résultat contenant les alertes des règles, les alertes IA et les métriques
     */
    public CompareResult analyze(MultipartFile file) throws Exception {

        // Étape 1 : on lit et parse le fichier CSV
        List<CSVRecord> records = csvParser.parse(file);

        if (records.isEmpty()) {
            throw new IllegalArgumentException("Le fichier CSV est vide ou mal formaté.");
        }

        // Étape 2 : on applique les règles de détection classiques (type IDS/Snort)
        List<RuleAlert> ruleAlerts = ruleEngine.analyze(records);

        // Étape 3 : on envoie les flux suspects à Gemini pour une analyse IA
        // .get() attend la fin de l'appel async avant de continuer
        List<LlmAlert> llmAlerts = llmService.analyze(records, ruleAlerts).get();

        // Étape 4 : on calcule les métriques (total de lignes + confiance moyenne IA)
        CompareMetrics metrics = computeMetrics(records, llmAlerts);

        return new CompareResult(ruleAlerts, llmAlerts, metrics);
    }

    /**
     * Calcule les métriques affichées dans le tableau de bord :
     * - le nombre total de lignes analysées
     * - la confiance moyenne des alertes IA (moyenne des scores retournés par Gemini)
     */
    private CompareMetrics computeMetrics(List<CSVRecord> records, List<LlmAlert> llmAlerts) {

        int totalRows = records.size();

        // Calcul de la confiance moyenne des alertes IA
        double llmAvgConfidence = 0.0;
        if (!llmAlerts.isEmpty()) {
            int totalConfidence = 0;
            for (LlmAlert alert : llmAlerts) {
                totalConfidence += alert.getConfidence();
            }
            llmAvgConfidence = (double) totalConfidence / llmAlerts.size();
        }

        return new CompareMetrics(totalRows, llmAvgConfidence);
    }
}

package com.threatdetector.backend.controller;

import com.threatdetector.backend.model.CompareResult;
import com.threatdetector.backend.service.AnalysisService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * Contrôleur REST qui expose les endpoints HTTP de l'application.
 * Il reçoit les requêtes du frontend Angular et délègue le traitement à l'AnalysisService.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200") // autorise les requêtes depuis le frontend Angular
public class AnalyzeController {

    // Service qui orchestre toute l'analyse (parsing CSV, règles, IA, métriques)
    private AnalysisService analysisService;

    // Injection du service via le constructeur (bonne pratique Spring)
    public AnalyzeController(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    /**
     * Endpoint principal : reçoit un fichier CSV et retourne le résultat de l'analyse.
     * Le fichier est envoyé en multipart/form-data par le frontend.
     *
     * @param file fichier CSV uploadé par l'utilisateur
     * @return résultat complet avec alertes règles, alertes IA et métriques
     */
    @PostMapping("/analyze")
    public CompareResult analyze(@RequestParam("file") MultipartFile file) throws Exception {
        return analysisService.analyze(file);
    }

    /**
     * Endpoint de santé pour vérifier que le backend est démarré.
     * Accessible via GET http://localhost:8080/health
     */
    @GetMapping("/health")
    public String health() {
        return "Threat Detector Backend — OK";
    }
}

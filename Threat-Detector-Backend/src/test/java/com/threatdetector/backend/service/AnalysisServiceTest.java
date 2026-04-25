package com.threatdetector.backend.service;

import com.threatdetector.backend.model.*;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;

import java.io.StringReader;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AnalysisServiceTest {

    @Mock private CsvParserService csvParser;
    @Mock private RuleEngineService ruleEngine;
    @Mock private LlmService llmService;

    private AnalysisService service;

    @BeforeEach
    void setUp() {
        service = new AnalysisService(csvParser, ruleEngine, llmService);
    }

    private List<CSVRecord> records(String csv) throws Exception {
        try (CSVParser parser = CSVFormat.DEFAULT.builder()
                .setHeader().setSkipHeaderRecord(true).setTrim(true)
                .build().parse(new StringReader(csv))) {
            return parser.getRecords();
        }
    }

    private MockMultipartFile emptyFile() {
        return new MockMultipartFile("file", "test.csv", "text/csv", new byte[0]);
    }

    private LlmAlert llmAlert(int row, int confidence) {
        LlmAlert a = new LlmAlert();
        a.setRow(row);
        a.setSeverity("HIGH");
        a.setConfidence(confidence);
        return a;
    }

    // ── Fichier vide ──────────────────────────────────────────────

    @Test
    void analyze_fichierVide_leveException() throws Exception {
        when(csvParser.parse(any())).thenReturn(List.of());
        assertThrows(IllegalArgumentException.class, () -> service.analyze(emptyFile()));
    }

    // ── Total des lignes ──────────────────────────────────────────

    @Test
    void analyze_totalLignesCorrect() throws Exception {
        List<CSVRecord> recs = records("Source IP\n1.1.1.1\n2.2.2.2\n3.3.3.3");

        when(csvParser.parse(any())).thenReturn(recs);
        when(ruleEngine.analyze(recs)).thenReturn(List.of());
        when(llmService.analyze(any(), any()))
            .thenReturn(CompletableFuture.completedFuture(List.of()));

        CompareResult result = service.analyze(emptyFile());

        assertEquals(3, result.getMetrics().getTotalRows());
    }

    // ── Confiance moyenne ─────────────────────────────────────────

    @Test
    void analyze_confianceMoyenne_calculeeCorrectement() throws Exception {
        List<CSVRecord> recs = records("Source IP\n1.1.1.1");
        List<LlmAlert> llmAlerts = List.of(llmAlert(1, 80), llmAlert(1, 60));

        when(csvParser.parse(any())).thenReturn(recs);
        when(ruleEngine.analyze(any())).thenReturn(List.of());
        when(llmService.analyze(any(), any()))
            .thenReturn(CompletableFuture.completedFuture(llmAlerts));

        CompareResult result = service.analyze(emptyFile());

        // (80 + 60) / 2 = 70.0
        assertEquals(70.0, result.getMetrics().getLlmAvgConfidence(), 0.001);
    }

    @Test
    void analyze_sansAlertesLlm_confianceEstZero() throws Exception {
        List<CSVRecord> recs = records("Source IP\n1.1.1.1");

        when(csvParser.parse(any())).thenReturn(recs);
        when(ruleEngine.analyze(any())).thenReturn(List.of());
        when(llmService.analyze(any(), any()))
            .thenReturn(CompletableFuture.completedFuture(List.of()));

        CompareResult result = service.analyze(emptyFile());

        assertEquals(0.0, result.getMetrics().getLlmAvgConfidence());
    }

    // ── Alertes transmises correctement ───────────────────────────

    @Test
    void analyze_alertesRegleEtLlmTransmises() throws Exception {
        List<CSVRecord> recs = records("Source IP\n1.1.1.1");
        List<RuleAlert> ruleAlerts = List.of(
            new RuleAlert(1, "PORT_SCAN_DETECTED", "HIGH", "desc")
        );
        List<LlmAlert> llmAlerts = List.of(llmAlert(1, 85));

        when(csvParser.parse(any())).thenReturn(recs);
        when(ruleEngine.analyze(recs)).thenReturn(ruleAlerts);
        when(llmService.analyze(eq(recs), eq(ruleAlerts)))
            .thenReturn(CompletableFuture.completedFuture(llmAlerts));

        CompareResult result = service.analyze(emptyFile());

        assertEquals(1, result.getRuleAlerts().size());
        assertEquals("PORT_SCAN_DETECTED", result.getRuleAlerts().get(0).getRule());
        assertEquals(1, result.getLlmAlerts().size());
        assertEquals(85, result.getLlmAlerts().get(0).getConfidence());
    }

    @Test
    void analyze_confianceMoyenne_alerteUnique() throws Exception {
        List<CSVRecord> recs = records("Source IP\n1.1.1.1");

        when(csvParser.parse(any())).thenReturn(recs);
        when(ruleEngine.analyze(any())).thenReturn(List.of());
        when(llmService.analyze(any(), any()))
            .thenReturn(CompletableFuture.completedFuture(List.of(llmAlert(1, 95))));

        CompareResult result = service.analyze(emptyFile());

        assertEquals(95.0, result.getMetrics().getLlmAvgConfidence(), 0.001);
    }
}

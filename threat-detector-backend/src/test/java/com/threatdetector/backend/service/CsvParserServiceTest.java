package com.threatdetector.backend.service;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.Test;

import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.*;

class CsvParserServiceTest {

    /** Crée un CSVRecord à partir d'une ligne d'en-tête et d'une ligne de données. */
    private CSVRecord record(String headers, String values) throws Exception {
        String csv = headers + "\n" + values;
        try (CSVParser parser = CSVFormat.DEFAULT.builder()
                .setHeader().setSkipHeaderRecord(true).setTrim(true)
                .build().parse(new StringReader(csv))) {
            return parser.getRecords().get(0);
        }
    }

    // ── safeDouble ────────────────────────────────────────────────

    @Test
    void safeDouble_valeurNormale() throws Exception {
        CSVRecord rec = record("Flow Bytes/s", "1234.56");
        assertEquals(1234.56, CsvParserService.safeDouble(rec, "Flow Bytes/s"), 0.001);
    }

    @Test
    void safeDouble_infinity_retourneZero() throws Exception {
        CSVRecord rec = record("Flow Bytes/s", "Infinity");
        assertEquals(0.0, CsvParserService.safeDouble(rec, "Flow Bytes/s"));
    }

    @Test
    void safeDouble_nan_retourneZero() throws Exception {
        CSVRecord rec = record("Flow Bytes/s", "NaN");
        assertEquals(0.0, CsvParserService.safeDouble(rec, "Flow Bytes/s"));
    }

    @Test
    void safeDouble_vide_retourneZero() throws Exception {
        // Colonne dummy pour que la ligne ne soit pas vide → Flow Bytes/s = ""
        CSVRecord rec = record("Flow Bytes/s,x", ",1");
        assertEquals(0.0, CsvParserService.safeDouble(rec, "Flow Bytes/s"));
    }

    @Test
    void safeDouble_colonneAbsente_retourneZero() throws Exception {
        CSVRecord rec = record("Autre", "42");
        assertEquals(0.0, CsvParserService.safeDouble(rec, "Flow Bytes/s"));
    }

    // ── safeLong / safeInt ────────────────────────────────────────

    @Test
    void safeLong_retourneValeur() throws Exception {
        CSVRecord rec = record("Flow Duration", "500000");
        assertEquals(500000L, CsvParserService.safeLong(rec, "Flow Duration"));
    }

    @Test
    void safeInt_retourneValeur() throws Exception {
        CSVRecord rec = record("SYN Flag Count", "3");
        assertEquals(3, CsvParserService.safeInt(rec, "SYN Flag Count"));
    }

    // ── safeStr ───────────────────────────────────────────────────

    @Test
    void safeStr_retourneValeur() throws Exception {
        CSVRecord rec = record("Source IP", "192.168.1.1");
        assertEquals("192.168.1.1", CsvParserService.safeStr(rec, "Source IP"));
    }

    @Test
    void safeStr_colonneAbsente_retourneVidee() throws Exception {
        CSVRecord rec = record("Autre", "val");
        assertEquals("", CsvParserService.safeStr(rec, "Source IP"));
    }

    // ── isAttack ──────────────────────────────────────────────────

    @Test
    void isAttack_benign_retourneFaux() throws Exception {
        CSVRecord rec = record("Label", "BENIGN");
        assertFalse(CsvParserService.isAttack(rec));
    }

    @Test
    void isAttack_ddos_retourneVrai() throws Exception {
        CSVRecord rec = record("Label", "DDoS");
        assertTrue(CsvParserService.isAttack(rec));
    }

    @Test
    void isAttack_portScan_retourneVrai() throws Exception {
        CSVRecord rec = record("Label", "PortScan");
        assertTrue(CsvParserService.isAttack(rec));
    }

    @Test
    void isAttack_labelVide_retourneFaux() throws Exception {
        // Colonne dummy pour que la ligne ne soit pas vide → Label = ""
        CSVRecord rec = record("Label,x", ",1");
        assertFalse(CsvParserService.isAttack(rec));
    }
}

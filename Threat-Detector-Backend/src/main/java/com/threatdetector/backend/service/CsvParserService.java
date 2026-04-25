package com.threatdetector.backend.service;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Service
public class CsvParserService {

    /**
     * Parse un fichier CSV CICIDS 2017 uploadé.
     * Gère les colonnes avec espaces, les valeurs Infinity/NaN.
     *
     * @return liste des enregistrements CSV (header inclus via map)
     */
    public List<CSVRecord> parse(MultipartFile file) {
        try (Reader reader = new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8)) {
            Iterable<CSVRecord> records = CSVFormat.DEFAULT
                    .builder()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .setTrim(true)
                    .setIgnoreEmptyLines(true)
                    .setIgnoreSurroundingSpaces(true)
                    .build()
                    .parse(reader);

            List<CSVRecord> result = new ArrayList<>();
            for (CSVRecord record : records) {
                result.add(record);
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Erreur de parsing CSV : " + e.getMessage(), e);
        }
    }

    /**
     * Lit une colonne double en tolérant Infinity/NaN → retourne 0.0.
     */
    public static double safeDouble(CSVRecord record, String col) {
        try {
            if (!record.isMapped(col)) return 0.0;
            String val = record.get(col).trim();
            if (val.isEmpty() || val.equalsIgnoreCase("Infinity")
                    || val.equalsIgnoreCase("NaN") || val.equals("inf")) return 0.0;
            return Double.parseDouble(val);
        } catch (NumberFormatException e) {
            return 0.0;
        }
    }

    /**
     * Lit une colonne long en tolérant les erreurs.
     */
    public static long safeLong(CSVRecord record, String col) {
        return (long) safeDouble(record, col);
    }

    /**
     * Lit une colonne int.
     */
    public static int safeInt(CSVRecord record, String col) {
        return (int) safeDouble(record, col);
    }

    /**
     * Retourne la valeur d'une colonne ou chaîne vide si absente.
     */
    public static String safeStr(CSVRecord record, String col) {
        try {
            return record.isMapped(col) ? record.get(col).trim() : "";
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Retourne true si le label indique une attaque (non-BENIGN).
     */
    public static boolean isAttack(CSVRecord record) {
        String label = safeStr(record, "Label").toUpperCase();
        return !label.isEmpty() && !label.equals("BENIGN");
    }
}

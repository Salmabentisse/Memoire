package com.threatdetector.backend.service;

import com.threatdetector.backend.model.RuleAlert;
import org.apache.commons.csv.CSVRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static com.threatdetector.backend.service.CsvParserService.*;

/**
 * Moteur de règles classique inspiré des IDS type Snort/Suricata.
 * Analyse les colonnes CICIDS 2017 par seuils fixes.
 */
@Service
public class RuleEngineService {

    @Value("${analysis.max-rule-alerts:100}")
    private int maxAlerts;

    public List<RuleAlert> analyze(List<CSVRecord> records) {
        List<RuleAlert> alerts = new ArrayList<>();

        for (int i = 0; i < records.size() && alerts.size() < maxAlerts; i++) {
            CSVRecord rec = records.get(i);
            int rowNum = i + 1;

            checkPortScan(rec, rowNum, alerts);
            checkDdosSynFlood(rec, rowNum, alerts);
            checkBruteForce(rec, rowNum, alerts);
            checkAnomalousVolume(rec, rowNum, alerts);
            checkFtpBounce(rec, rowNum, alerts);
            checkDnsAmplification(rec, rowNum, alerts);
        }

        return alerts;
    }

    // ── Règle 1 : Port Scan ────────────────────────────────────────────────────
    private void checkPortScan(CSVRecord rec, int row, List<RuleAlert> alerts) {
        int synFlags = safeInt(rec, "SYN Flag Count");
        int ackFlags = safeInt(rec, "ACK Flag Count");
        long flowDuration = safeLong(rec, "Flow Duration");
        double flowPkts = safeDouble(rec, "Flow Packets/s");
        int dstPort = safeInt(rec, "Destination Port");

        // SYN sans ACK sur courte durée — pattern classique nmap -sS
        boolean isSynStealth = synFlags > 0 && ackFlags == 0 && flowDuration < 500_000;
        // Ou balayage rapide de ports bas
        boolean isPortSweep = dstPort < 1024 && flowPkts > 1000 && flowDuration < 100_000;

        if (isSynStealth || isPortSweep) {
            String srcIp = safeStr(rec, "Source IP");
            String dstIp = safeStr(rec, "Destination IP");
            alerts.add(new RuleAlert(row, "PORT_SCAN_DETECTED", "HIGH",
                    String.format("Scan SYN Stealth détecté depuis %s vers %s — port %d, %d paquets/s, durée %d μs.",
                            srcIp.isEmpty() ? "IP inconnue" : srcIp,
                            dstIp.isEmpty() ? "IP inconnue" : dstIp,
                            dstPort, (int) flowPkts, flowDuration)));
        }
    }

    // ── Règle 2 : DDoS SYN Flood ──────────────────────────────────────────────
    private void checkDdosSynFlood(CSVRecord rec, int row, List<RuleAlert> alerts) {
        double flowPkts = safeDouble(rec, "Flow Packets/s");
        int synFlags = safeInt(rec, "SYN Flag Count");
        int ackFlags = safeInt(rec, "ACK Flag Count");
        double flowBytes = safeDouble(rec, "Flow Bytes/s");

        // Inondation massive de SYN sans ACK (connexions jamais établies)
        if (flowPkts > 5_000 && synFlags > 0 && ackFlags == 0) {
            String dstIp = safeStr(rec, "Destination IP");
            int dstPort = safeInt(rec, "Destination Port");
            alerts.add(new RuleAlert(row, "DDOS_SYN_FLOOD", "HIGH",
                    String.format("Flood SYN massif vers %s:%d — %.0f paquets/s, %.0f octets/s, 0 connexion établie.",
                            dstIp.isEmpty() ? "IP inconnue" : dstIp,
                            dstPort, flowPkts, flowBytes)));
        }
    }

    // ── Règle 3 : Brute Force SSH / FTP ───────────────────────────────────────
    private void checkBruteForce(CSVRecord rec, int row, List<RuleAlert> alerts) {
        int dstPort = safeInt(rec, "Destination Port");
        long totalFwdPkts = safeLong(rec, "Total Fwd Packets");
        long flowDuration = safeLong(rec, "Flow Duration");
        double fwdPktsPerSec = safeDouble(rec, "Fwd Packets/s");

        boolean isSsh = dstPort == 22;
        boolean isFtpPatator = dstPort == 21;

        if ((isSsh || isFtpPatator) && totalFwdPkts > 5 && flowDuration < 10_000_000) {
            String protocol = isSsh ? "SSH" : "FTP";
            String srcIp = safeStr(rec, "Source IP");
            String severity = fwdPktsPerSec > 50 ? "HIGH" : "MEDIUM";
            alerts.add(new RuleAlert(row, "BRUTE_FORCE_" + protocol, severity,
                    String.format("Tentative de brute-force %s depuis %s — %d paquets envoyés en %d μs (%.0f pkt/s).",
                            protocol,
                            srcIp.isEmpty() ? "IP inconnue" : srcIp,
                            totalFwdPkts, flowDuration, fwdPktsPerSec)));
        }
    }

    // ── Règle 4 : Volume de trafic anormal ────────────────────────────────────
    private void checkAnomalousVolume(CSVRecord rec, int row, List<RuleAlert> alerts) {
        double flowBytes = safeDouble(rec, "Flow Bytes/s");
        long totalFwdBytes = safeLong(rec, "Total Length of Fwd Packets");
        int dstPort = safeInt(rec, "Destination Port");

        // Exclure les ports légitimes connus à haut débit
        boolean isHighThroughputPort = dstPort == 443 || dstPort == 80;

        if (flowBytes > 2_000_000 && !isHighThroughputPort && totalFwdBytes > 100_000) {
            String srcIp = safeStr(rec, "Source IP");
            alerts.add(new RuleAlert(row, "ANOMALOUS_TRAFFIC_VOLUME", "MEDIUM",
                    String.format("Volume sortant anormal depuis %s — %.2f MB/s, %d octets totaux transmis.",
                            srcIp.isEmpty() ? "IP inconnue" : srcIp,
                            flowBytes / 1_000_000, totalFwdBytes)));
        }
    }

    // ── Règle 5 : FTP Bounce ──────────────────────────────────────────────────
    private void checkFtpBounce(CSVRecord rec, int row, List<RuleAlert> alerts) {
        int dstPort = safeInt(rec, "Destination Port");
        int finFlags = safeInt(rec, "FIN Flag Count");
        int rstFlags = safeInt(rec, "RST Flag Count");
        long totalBwdPkts = safeLong(rec, "Total Backward Packets");

        if (dstPort == 21 && finFlags == 0 && rstFlags == 0 && totalBwdPkts > 3) {
            String srcIp = safeStr(rec, "Source IP");
            String dstIp = safeStr(rec, "Destination IP");
            alerts.add(new RuleAlert(row, "FTP_BOUNCE_ATTEMPT", "MEDIUM",
                    String.format("Tentative de rebond FTP de %s vers %s — session sans FIN/RST, commande PORT suspecte.",
                            srcIp.isEmpty() ? "IP inconnue" : srcIp,
                            dstIp.isEmpty() ? "IP inconnue" : dstIp)));
        }
    }

    // ── Règle 6 : DNS Amplification ───────────────────────────────────────────
    private void checkDnsAmplification(CSVRecord rec, int row, List<RuleAlert> alerts) {
        int dstPort = safeInt(rec, "Destination Port");
        double flowBytes = safeDouble(rec, "Flow Bytes/s");
        long bwdBytes = safeLong(rec, "Total Length of Bwd Packets");
        long fwdBytes = safeLong(rec, "Total Length of Fwd Packets");

        // DNS (port 53) avec ratio réponse/requête élevé (amplification)
        boolean highAmplification = fwdBytes > 0 && (double) bwdBytes / fwdBytes > 10;

        if (dstPort == 53 && (flowBytes > 50_000 || highAmplification)) {
            String srcIp = safeStr(rec, "Source IP");
            double ampFactor = fwdBytes > 0 ? (double) bwdBytes / fwdBytes : 0;
            alerts.add(new RuleAlert(row, "DNS_AMPLIFICATION", "HIGH",
                    String.format("Amplification DNS depuis %s — facteur x%.0f, %.0f octets/s. Résolveur ouvert exploité.",
                            srcIp.isEmpty() ? "IP inconnue" : srcIp,
                            ampFactor, flowBytes)));
        }
    }
}

package com.threatdetector.backend.service;

import com.threatdetector.backend.model.RuleAlert;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.StringReader;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineServiceTest {

    private RuleEngineService service;

    @BeforeEach
    void setUp() {
        service = new RuleEngineService();
        ReflectionTestUtils.setField(service, "maxAlerts", 100);
    }

    /** Crée une liste de CSVRecords à partir d'une chaîne CSV (header + données). */
    private List<CSVRecord> records(String csv) throws Exception {
        try (CSVParser parser = CSVFormat.DEFAULT.builder()
                .setHeader().setSkipHeaderRecord(true).setTrim(true)
                .build().parse(new StringReader(csv))) {
            return parser.getRecords();
        }
    }

    // ── Règle 1 : Port Scan ───────────────────────────────────────

    @Test
    void portScan_synSansAck_declenche() throws Exception {
        // SYN=1, ACK=0, durée < 500 000 → scan SYN stealth
        List<CSVRecord> recs = records(
            "SYN Flag Count,ACK Flag Count,Flow Duration,Flow Packets/s,Destination Port,Source IP,Destination IP\n" +
            "1,0,400000,500,8080,192.168.1.1,10.0.0.1"
        );
        assertTrue(hasRule(service.analyze(recs), "PORT_SCAN_DETECTED"));
    }

    @Test
    void portScan_avecAck_neDeclenchePas() throws Exception {
        // SYN=1 mais ACK=1 → connexion établie normale, pas un scan
        List<CSVRecord> recs = records(
            "SYN Flag Count,ACK Flag Count,Flow Duration,Flow Packets/s,Destination Port,Source IP,Destination IP\n" +
            "1,1,400000,500,8080,192.168.1.1,10.0.0.1"
        );
        assertFalse(hasRule(service.analyze(recs), "PORT_SCAN_DETECTED"));
    }

    // ── Règle 2 : DDoS SYN Flood ─────────────────────────────────

    @Test
    void ddosSynFlood_volumeMassif_declenche() throws Exception {
        // flowPkts > 5000, SYN > 0, ACK == 0
        List<CSVRecord> recs = records(
            "Flow Packets/s,SYN Flag Count,ACK Flag Count,Flow Bytes/s,Destination IP,Destination Port\n" +
            "6000,1,0,1000000,10.0.0.1,80"
        );
        assertTrue(hasRule(service.analyze(recs), "DDOS_SYN_FLOOD"));
    }

    @Test
    void ddosSynFlood_volumeFaible_neDeclenchePas() throws Exception {
        // flowPkts = 100 → sous le seuil de 5000
        List<CSVRecord> recs = records(
            "Flow Packets/s,SYN Flag Count,ACK Flag Count,Flow Bytes/s,Destination IP,Destination Port\n" +
            "100,1,0,1000,10.0.0.1,80"
        );
        assertFalse(hasRule(service.analyze(recs), "DDOS_SYN_FLOOD"));
    }

    // ── Règle 3 : Brute Force ─────────────────────────────────────

    @Test
    void bruteForce_ssh_declenche() throws Exception {
        // Port 22, > 5 paquets, durée courte
        List<CSVRecord> recs = records(
            "Destination Port,Total Fwd Packets,Flow Duration,Fwd Packets/s,Source IP\n" +
            "22,10,5000000,30,192.168.1.100"
        );
        assertTrue(hasRule(service.analyze(recs), "BRUTE_FORCE_SSH"));
    }

    @Test
    void bruteForce_ftp_declenche() throws Exception {
        List<CSVRecord> recs = records(
            "Destination Port,Total Fwd Packets,Flow Duration,Fwd Packets/s,Source IP\n" +
            "21,10,5000000,30,192.168.1.100"
        );
        assertTrue(hasRule(service.analyze(recs), "BRUTE_FORCE_FTP"));
    }

    @Test
    void bruteForce_ssh_peuDePaquets_neDeclenchePas() throws Exception {
        // Seulement 3 paquets → sous le seuil de 5
        List<CSVRecord> recs = records(
            "Destination Port,Total Fwd Packets,Flow Duration,Fwd Packets/s,Source IP\n" +
            "22,3,5000000,10,192.168.1.100"
        );
        assertFalse(hasRule(service.analyze(recs), "BRUTE_FORCE_SSH"));
    }

    // ── Règle 4 : Volume anormal ──────────────────────────────────

    @Test
    void volumeAnormal_declenche() throws Exception {
        // flowBytes > 2 000 000, port != 80/443, fwdBytes > 100 000
        List<CSVRecord> recs = records(
            "Flow Bytes/s,Total Length of Fwd Packets,Destination Port,Source IP\n" +
            "3000000,200000,8080,192.168.1.1"
        );
        assertTrue(hasRule(service.analyze(recs), "ANOMALOUS_TRAFFIC_VOLUME"));
    }

    @Test
    void volumeAnormal_port443_neDeclenchePas() throws Exception {
        // HTTPS légitime — exclu de la règle
        List<CSVRecord> recs = records(
            "Flow Bytes/s,Total Length of Fwd Packets,Destination Port,Source IP\n" +
            "3000000,200000,443,192.168.1.1"
        );
        assertFalse(hasRule(service.analyze(recs), "ANOMALOUS_TRAFFIC_VOLUME"));
    }

    // ── Règle 5 : FTP Bounce ──────────────────────────────────────

    @Test
    void ftpBounce_declenche() throws Exception {
        // Port 21, pas de FIN/RST, paquets retour > 3
        List<CSVRecord> recs = records(
            "Destination Port,FIN Flag Count,RST Flag Count,Total Backward Packets,Source IP,Destination IP\n" +
            "21,0,0,5,192.168.1.1,10.0.0.1"
        );
        assertTrue(hasRule(service.analyze(recs), "FTP_BOUNCE_ATTEMPT"));
    }

    @Test
    void ftpBounce_avecFin_neDeclenchePas() throws Exception {
        // FIN=1 → session fermée normalement, pas un bounce
        List<CSVRecord> recs = records(
            "Destination Port,FIN Flag Count,RST Flag Count,Total Backward Packets,Source IP,Destination IP\n" +
            "21,1,0,5,192.168.1.1,10.0.0.1"
        );
        assertFalse(hasRule(service.analyze(recs), "FTP_BOUNCE_ATTEMPT"));
    }

    // ── Règle 6 : DNS Amplification ───────────────────────────────

    @Test
    void dnsAmplification_hautDebit_declenche() throws Exception {
        // Port 53, flowBytes > 50 000
        List<CSVRecord> recs = records(
            "Destination Port,Flow Bytes/s,Total Length of Bwd Packets,Total Length of Fwd Packets,Source IP\n" +
            "53,60000,1000,10,1.2.3.4"
        );
        assertTrue(hasRule(service.analyze(recs), "DNS_AMPLIFICATION"));
    }

    @Test
    void dnsAmplification_portDifferent_neDeclenchePas() throws Exception {
        // Port 8053 au lieu de 53 → pas de la règle DNS
        List<CSVRecord> recs = records(
            "Destination Port,Flow Bytes/s,Total Length of Bwd Packets,Total Length of Fwd Packets,Source IP\n" +
            "8053,60000,1000,10,1.2.3.4"
        );
        assertFalse(hasRule(service.analyze(recs), "DNS_AMPLIFICATION"));
    }

    // ── Cas limites ───────────────────────────────────────────────

    @Test
    void fichierVide_retourneAucuneAlerte() throws Exception {
        List<CSVRecord> recs = records("SYN Flag Count,ACK Flag Count");
        assertTrue(service.analyze(recs).isEmpty());
    }

    @Test
    void maxAlerts_limiteRespectee() throws Exception {
        ReflectionTestUtils.setField(service, "maxAlerts", 3);
        // 10 lignes qui déclenchent toutes PORT_SCAN
        StringBuilder csv = new StringBuilder(
            "SYN Flag Count,ACK Flag Count,Flow Duration,Flow Packets/s,Destination Port,Source IP,Destination IP\n"
        );
        for (int i = 0; i < 10; i++) csv.append("1,0,400000,500,8080,1.1.1.1,2.2.2.2\n");

        List<RuleAlert> alerts = service.analyze(records(csv.toString()));
        assertEquals(3, alerts.size());
    }

    // ── Helpers ───────────────────────────────────────────────────

    private boolean hasRule(List<RuleAlert> alerts, String rule) {
        return alerts.stream().anyMatch(a -> a.getRule().equals(rule));
    }
}

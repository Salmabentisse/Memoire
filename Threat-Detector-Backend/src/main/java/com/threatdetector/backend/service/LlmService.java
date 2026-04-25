package com.threatdetector.backend.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatdetector.backend.model.LlmAlert;
import com.threatdetector.backend.model.RuleAlert;
import org.apache.commons.csv.CSVRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static com.threatdetector.backend.service.CsvParserService.*;

/**
 * Service responsable de l'analyse des flux réseau par intelligence artificielle.
 * Il envoie les flux suspects à l'API Gemini et récupère les alertes générées.
 */
@Service
public class LlmService {

    // URL de l'API Gemini — on remplace %s par le modèle et la clé API
    private static final String GEMINI_URL =
            "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s";

    // Clé API lue depuis application.properties
    @Value("${gemini.api.key}")
    private String apiKey;

    // Nom du modèle Gemini à utiliser (par défaut gemini-2.5-flash)
    @Value("${gemini.model:gemini-2.5-flash}")
    private String model;

    // Nombre maximum de lignes CSV envoyées à Gemini par analyse
    @Value("${analysis.max-llm-rows:30}")
    private int maxLlmRows;

    // ObjectMapper de Jackson pour convertir des objets Java en JSON et inversement
    private final ObjectMapper mapper = new ObjectMapper();

    // Client HTTP Java pour envoyer la requête à l'API Gemini
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    /**
     * Méthode principale d'analyse par IA.
     * Elle est marquée @Async pour ne pas bloquer le thread HTTP pendant l'attente de Gemini.
     * Elle retourne un CompletableFuture que l'appelant peut attendre avec .get()
     *
     * @param records     toutes les lignes du CSV uploadé
     * @param ruleAlerts  alertes déjà détectées par le moteur de règles classiques
     * @return liste des alertes IA détectées par Gemini
     */
    @Async
    public CompletableFuture<List<LlmAlert>> analyze(List<CSVRecord> records, List<RuleAlert> ruleAlerts) throws Exception {

        // Étape 1 : on récupère les numéros de lignes déjà signalées par les règles classiques
        Set<Integer> suspectRows = new HashSet<>();
        for (RuleAlert alert : ruleAlerts) {
            suspectRows.add(alert.getRow());
        }

        // On ajoute aussi les lignes voisines pour donner plus de contexte à Gemini
        addNeighborRows(suspectRows, records.size());

        // Étape 2 : on sélectionne les enregistrements CSV correspondants aux lignes suspectes
        List<CSVRecord> rowsToAnalyze = new ArrayList<>();
        List<Integer> rowNumbers = new ArrayList<>();

        for (int i = 0; i < records.size(); i++) {
            if (rowsToAnalyze.size() >= maxLlmRows) break; // on ne dépasse pas la limite
            if (suspectRows.contains(i + 1)) {
                rowsToAnalyze.add(records.get(i));
                rowNumbers.add(i + 1); // les lignes CSV commencent à 1
            }
        }

        // Si aucune ligne suspecte trouvée, on retourne une liste vide directement
        if (rowsToAnalyze.isEmpty()) {
            return CompletableFuture.completedFuture(new ArrayList<>());
        }

        // Étape 3 : on envoie les flux suspects à Gemini et on récupère ses alertes
        List<LlmAlert> alerts = callGeminiApi(rowsToAnalyze, rowNumbers);

        // Étape 4 : on enrichit chaque alerte avec les données réseau extraites du CSV
        // (Gemini ne connaît que le contenu du prompt, pas les données brutes du CSV)
        Map<Integer, CSVRecord> rowToRecord = new HashMap<>();
        for (int i = 0; i < rowNumbers.size(); i++) {
            rowToRecord.put(rowNumbers.get(i), rowsToAnalyze.get(i));
        }

        for (LlmAlert alert : alerts) {
            CSVRecord rec = rowToRecord.get(alert.getRow());
            if (rec != null) {
                // On recopie les infos réseau depuis le CSV directement dans l'alerte
                alert.setSourceIp(safeStr(rec, "Source IP"));
                alert.setDestIp(safeStr(rec, "Destination IP"));
                alert.setSrcPort(safeInt(rec, "Source Port"));
                alert.setDstPort(safeInt(rec, "Destination Port"));
                alert.setProtocol(resolveProtocol(safeInt(rec, "Protocol")));
            }

            // Si Gemini n'a pas renvoyé le nom de la menace, on essaie de le deviner
            if (alert.getThreatType() == null || alert.getThreatType().isBlank()) {
                alert.setThreatType(guessThreatType(alert.getExplanation()));
            }
        }

        // On retourne les alertes dans un CompletableFuture (obligatoire avec @Async)
        return CompletableFuture.completedFuture(alerts);
    }

    /**
     * Envoie les flux réseau à l'API Gemini et récupère la liste d'alertes JSON.
     */
    private List<LlmAlert> callGeminiApi(List<CSVRecord> rows, List<Integer> rowNumbers) throws Exception {
        String url = String.format(GEMINI_URL, model, apiKey);

        // Construction du prompt complet (instructions système + données des flux)
        String prompt = buildPrompt(rows, rowNumbers);
        String fullText = buildSystemPrompt() + "\n\n" + prompt;

        // Construction du corps de la requête JSON attendu par l'API Gemini
        Map<String, Object> part = new HashMap<>();
        part.put("text", fullText);

        Map<String, Object> content = new HashMap<>();
        content.put("parts", List.of(part));

        Map<String, Object> body = new HashMap<>();
        body.put("contents", List.of(content));

        String requestBody = mapper.writeValueAsString(body);

        // Création et envoi de la requête HTTP POST vers Gemini
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(120)) // Gemini peut prendre jusqu'à 2 minutes
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        System.out.println("⏳ [LlmService] Envoi de la requête à Gemini...");
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // Si Gemini retourne une erreur HTTP, on lance une exception
        if (response.statusCode() != 200) {
            throw new RuntimeException("Erreur Gemini HTTP " + response.statusCode() + " : " + response.body());
        }

        // On extrait le texte de la réponse JSON de Gemini
        JsonNode root = mapper.readTree(response.body());
        String responseText = root
                .path("candidates").get(0)
                .path("content")
                .path("parts").get(0)
                .path("text").asText();

        // Gemini entoure parfois la réponse JSON de balises markdown ```json ... ```
        // On les supprime pour obtenir du JSON pur
        responseText = responseText.trim();
        if (responseText.startsWith("```")) {
            responseText = responseText.replaceAll("^```[a-zA-Z]*\\n?", "");
            responseText = responseText.replaceAll("```$", "");
            responseText = responseText.trim();
        }

        System.out.println("🔍 [LlmService] Réponse brute Gemini : " + responseText);

        // On désérialise le JSON en liste d'objets LlmAlert avec Jackson
        List<LlmAlert> alerts = mapper.readValue(responseText, new TypeReference<List<LlmAlert>>() {});
        System.out.println("✅ [LlmService] Gemini a répondu avec " + alerts.size() + " alertes.");
        return alerts;
    }

    /**
     * Instructions envoyées à Gemini pour lui expliquer comment répondre.
     * On lui demande d'être strict et de ne remonter que les vraies menaces.
     */
    private String buildSystemPrompt() {
        return "Tu es un expert en cybersécurité et analyse de trafic réseau. "
                + "Tu analyses des flux réseau issus du dataset CICIDS 2017. "

                // Règle anti-faux positifs : Gemini ne doit signaler que les vraies attaques
                + "RÈGLE PRINCIPALE : N'inclus dans ta réponse QUE les flux qui sont de véritables menaces. "
                + "Si un flux est normal, bénin ou simplement inhabituel sans preuve d'attaque, NE l'inclus PAS. "
                + "Il vaut mieux manquer une alerte que générer un faux positif. "
                + "N'inclus un flux que si tu es certain à plus de 60% que c'est une attaque réelle. "

                // Format de réponse attendu
                + "IMPORTANT : Réponds UNIQUEMENT avec un tableau JSON valide, sans texte avant ni après, sans markdown. "
                + "Si aucun flux n'est une vraie menace, réponds avec un tableau vide : []. "
                + "Chaque élément du tableau doit avoir EXACTEMENT ces 6 champs : "
                + "{ "
                + "\"row\": <numéro de ligne>, "
                + "\"threatType\": \"<nom court de la menace en français, ex: Port Scan, DDoS, Brute Force SSH, Paquet Malformé>\", "
                + "\"severity\": \"<LOW ou MEDIUM ou HIGH>\", "
                + "\"explanation\": \"<explication en français, 2-3 phrases>\", "
                + "\"recommendation\": \"<action corrective en français, 1-2 phrases>\", "
                + "\"confidence\": <nombre entier entre 0 et 100, uniquement si > 60> "
                + "}";
    }

    /**
     * Construit le texte du prompt avec les données de chaque flux réseau suspect.
     * On inclut uniquement les colonnes utiles pour l'analyse de sécurité.
     */
    private String buildPrompt(List<CSVRecord> rows, List<Integer> rowNumbers) {
        StringBuilder sb = new StringBuilder();
        sb.append("Analyse les flux réseau suivants et retourne un tableau JSON :\n\n");

        for (int i = 0; i < rows.size(); i++) {
            CSVRecord rec = rows.get(i);

            // En-tête du flux avec son numéro de ligne dans le CSV original
            sb.append("=== Flux ligne ").append(rowNumbers.get(i)).append(" ===\n");

            // Informations réseau de base (IP, ports, protocole)
            appendField(sb, rec, "Source IP");
            appendField(sb, rec, "Source Port");
            appendField(sb, rec, "Destination IP");
            appendField(sb, rec, "Destination Port");
            appendField(sb, rec, "Protocol");

            // Statistiques temporelles du flux
            appendField(sb, rec, "Flow Duration");
            appendField(sb, rec, "Total Fwd Packets");
            appendField(sb, rec, "Total Backward Packets");
            appendField(sb, rec, "Flow Bytes/s");
            appendField(sb, rec, "Flow Packets/s");

            // Drapeaux TCP (utiles pour détecter scans, floods, etc.)
            appendField(sb, rec, "SYN Flag Count");
            appendField(sb, rec, "ACK Flag Count");
            appendField(sb, rec, "FIN Flag Count");
            appendField(sb, rec, "RST Flag Count");

            // Taille moyenne des paquets
            appendField(sb, rec, "Packet Length Mean");
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Ajoute une ligne "colonne: valeur" au prompt seulement si la valeur est présente.
     */
    private void appendField(StringBuilder sb, CSVRecord rec, String columnName) {
        String value = safeStr(rec, columnName);
        if (!value.isEmpty()) {
            sb.append(columnName).append(": ").append(value).append("\n");
        }
    }

    /**
     * Si Gemini n'a pas renvoyé le champ threatType, on essaie de deviner le type
     * de menace en cherchant des mots-clés dans l'explication.
     */
    private String guessThreatType(String explanation) {
        if (explanation == null) return "Activité Suspecte";

        String text = explanation.toLowerCase();

        if (text.contains("ddos") || text.contains("flood") || text.contains("déni de service")) {
            return "DDoS";
        }
        if (text.contains("brute force") || text.contains("force brute")) {
            return "Brute Force";
        }
        if (text.contains("ssh")) {
            return "Brute Force SSH";
        }
        if (text.contains("scan") || text.contains("balayage")) {
            return "Port Scan";
        }
        if (text.contains("malform") || text.contains("protocole 0") || text.contains("hopopt")) {
            return "Paquet Malformé";
        }
        if (text.contains("évasion") || text.contains("furtif") || text.contains("tunnel")) {
            return "Évasion de Détection";
        }
        if (text.contains("exfiltration") || text.contains("fuite")) {
            return "Exfiltration";
        }
        if (text.contains("botnet") || text.contains("c&c") || text.contains("c2")) {
            return "Botnet / C2";
        }

        return "Activité Suspecte";
    }

    /**
     * Convertit le code numérique du protocole réseau en nom lisible.
     * Dans CICIDS 2017, le protocole est stocké sous forme de nombre (ex: 6 = TCP).
     */
    private String resolveProtocol(int code) {
        if (code == 6)  return "TCP";
        if (code == 17) return "UDP";
        if (code == 1)  return "ICMP";
        if (code == 0)  return "HOPOPT";
        if (code == 58) return "ICMPv6";
        return String.valueOf(code); // protocole inconnu : on retourne le numéro brut
    }

    /**
     * Ajoute les lignes voisines (+/- 2) des lignes suspectes dans l'ensemble à analyser.
     * Cela permet à Gemini d'avoir du contexte autour de chaque flux suspect.
     * On ajoute aussi quelques lignes aléatoires pour détecter les attaques "cachées".
     */
    private void addNeighborRows(Set<Integer> suspectRows, int totalRows) {
        Set<Integer> toAdd = new HashSet<>();

        // Ajoute les 2 lignes avant et après chaque ligne suspecte
        for (int row : suspectRows) {
            for (int delta = 1; delta <= 2; delta++) {
                if (row + delta <= totalRows) toAdd.add(row + delta);
                if (row - delta >= 1)         toAdd.add(row - delta);
            }
        }

        // Ajoute des lignes réparties uniformément dans le fichier (échantillonnage)
        int step = Math.max(1, totalRows / 5);
        for (int i = step; i <= totalRows; i += step) {
            if (suspectRows.size() + toAdd.size() >= maxLlmRows) break;
            if (!suspectRows.contains(i)) toAdd.add(i);
        }

        suspectRows.addAll(toAdd);
    }
}

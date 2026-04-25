package com.threatdetector.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Représente une alerte générée par l'intelligence artificielle Gemini.
 *
 * Les champs avec @JsonProperty sont remplis par Jackson en désérialisant
 * la réponse JSON de Gemini (row, threatType, severity, explanation, etc.).
 *
 * Les champs sans @JsonProperty (sourceIp, destIp, etc.) sont enrichis manuellement
 * par le LlmService après la réponse de Gemini, en lisant directement le CSV.
 *
 * @JsonIgnoreProperties(ignoreUnknown = true) : si Gemini renvoie des champs
 * inconnus dans son JSON, Jackson les ignore au lieu de planter.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LlmAlert {

    // Champs retournés directement par Gemini dans sa réponse JSON
    @JsonProperty("row")
    private int row;              // numéro de la ligne dans le CSV

    @JsonProperty("threatType")
    private String threatType;    // nom court de la menace (ex: "DDoS", "Port Scan")

    @JsonProperty("severity")
    private String severity;      // niveau de gravité : LOW, MEDIUM ou HIGH

    @JsonProperty("explanation")
    private String explanation;   // explication de la menace en français (2-3 phrases)

    @JsonProperty("recommendation")
    private String recommendation; // action corrective recommandée

    @JsonProperty("confidence")
    private int confidence;       // score de confiance entre 0 et 100

    // Champs enrichis depuis le CSV après la réponse Gemini (Gemini ne connaît pas le CSV brut)
    private String sourceIp;  // adresse IP source du flux réseau
    private String destIp;    // adresse IP destination du flux réseau
    private int srcPort;      // port source
    private int dstPort;      // port destination
    private String protocol;  // protocole : TCP, UDP, ICMP, etc.

    // Constructeur vide requis par Jackson
    public LlmAlert() {}

    // ── Getters ──────────────────────────────────────────────────
    public int getRow()                { return row; }
    public String getThreatType()      { return threatType; }
    public String getSeverity()        { return severity; }
    public String getExplanation()     { return explanation; }
    public String getRecommendation()  { return recommendation; }
    public int getConfidence()         { return confidence; }
    public String getSourceIp()        { return sourceIp; }
    public String getDestIp()          { return destIp; }
    public int getSrcPort()            { return srcPort; }
    public int getDstPort()            { return dstPort; }
    public String getProtocol()        { return protocol; }

    // ── Setters — utilisés par LlmService pour enrichir l'alerte avec les données CSV ──
    public void setRow(int row)                          { this.row = row; }
    public void setThreatType(String threatType)         { this.threatType = threatType; }
    public void setSeverity(String severity)             { this.severity = severity; }
    public void setExplanation(String explanation)       { this.explanation = explanation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    public void setConfidence(int confidence)            { this.confidence = confidence; }
    public void setSourceIp(String sourceIp)             { this.sourceIp = sourceIp; }
    public void setDestIp(String destIp)                 { this.destIp = destIp; }
    public void setSrcPort(int srcPort)                  { this.srcPort = srcPort; }
    public void setDstPort(int dstPort)                  { this.dstPort = dstPort; }
    public void setProtocol(String protocol)             { this.protocol = protocol; }
}

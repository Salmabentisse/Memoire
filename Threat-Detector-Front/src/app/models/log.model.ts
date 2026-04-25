/**
 * Alerte générée par le moteur de règles classique (type IDS/Snort).
 * Elle correspond à une règle déclenchée sur un flux réseau du CSV.
 */
export interface RuleAlert {
  row: number;          // numéro de la ligne dans le CSV (commence à 1)
  rule: string;         // identifiant de la règle (ex: "PORT_SCAN_DETECTED")
  severity: 'LOW' | 'MEDIUM' | 'HIGH';  // niveau de gravité
  description: string;  // message descriptif avec les détails du flux
}

/**
 * Alerte générée par l'intelligence artificielle Gemini.
 * Elle contient les informations retournées par Gemini + les données réseau
 * extraites du CSV par le backend (sourceIp, destIp, ports, protocole).
 */
export interface LlmAlert {
  row: number;           // numéro de la ligne dans le CSV
  threatType: string;    // nom court de la menace (ex: "DDoS", "Port Scan", "Brute Force SSH")
  severity: 'LOW' | 'MEDIUM' | 'HIGH';  // niveau de gravité estimé par Gemini
  explanation: string;   // explication en français (2-3 phrases) fournie par Gemini
  recommendation: string; // action corrective recommandée par Gemini
  confidence: number;    // score de confiance entre 0 et 100 (toujours > 60 dans nos résultats)
  // Informations réseau extraites du CSV par le backend (peuvent être vides si colonnes absentes)
  sourceIp: string;      // adresse IP source du flux
  destIp: string;        // adresse IP destination du flux
  srcPort: number;       // port source
  dstPort: number;       // port destination
  protocol: string;      // protocole réseau (TCP, UDP, ICMP, etc.)
}

/**
 * Métriques affichées dans le tableau de bord après l'analyse.
 */
export interface CompareMetrics {
  totalRows: number;         // nombre total de lignes dans le CSV analysé
  llmAvgConfidence: number;  // score de confiance moyen des alertes IA (0-100)
}

/**
 * Résultat complet de l'analyse renvoyé par le backend.
 * Regroupe les alertes des deux approches et les métriques de comparaison.
 */
export interface CompareResult {
  ruleAlerts: RuleAlert[];  // alertes détectées par les règles classiques
  llmAlerts: LlmAlert[];    // alertes détectées par Gemini
  metrics: CompareMetrics;  // statistiques de performance des deux approches
}

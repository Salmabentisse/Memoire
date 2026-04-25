# ThreatDetector

Projet de fin d'études — Master en cybersécurité.

L'idée de base : les outils IDS classiques (Snort, Suricata) génèrent des dizaines voire des centaines d'alertes brutes sur un fichier de logs réseau. Sans contexte, sans explication, sans priorisation. Un analyste SOC qui reçoit 101 alertes d'un coup ne sait pas par où commencer.

ThreatDetector essaie de résoudre ça en combinant un moteur de règles classique avec Google Gemini pour qualifier les alertes les plus suspectes et fournir une explication en langage naturel.

---

## Ce que ça fait concrètement

On upload un fichier CSV (format CICIDS 2017), le backend le parse, applique 6 règles de détection, envoie les flux suspects à Gemini, et le frontend affiche le résultat en 3 onglets : règles classiques, détection IA, et une vue comparaison entre les deux.

Sur notre fichier de test (225 745 connexions réseau, fichier DDoS CICIDS 2017) :
- Moteur de règles → 101 alertes
- Gemini → 8 menaces qualifiées avec explication et recommandation, confiance moyenne à 85.6%

---

## Stack technique

**Backend** — Spring Boot, Java 17, Apache Commons CSV  
**Frontend** — Angular 21, Angular Material, Angular Signals  
**IA** — API Google Gemini 2.5 Flash  
**Dataset** — CICIDS 2017 (Canadian Institute for Cybersecurity)

---

## Structure du repo

```
Threat-Detector-Front/    → application Angular
threat-detector-backend/  → API Spring Boot
```

---

## Lancer le projet

**Backend**

Avant de lancer, ouvrir `Threat-Detector-Backend/src/main/resources/application.properties` et renseigner la clé API :

```properties
gemini.api.key=TA_CLE_API_ICI
```

La clé s'obtient sur [Google AI Studio](https://aistudio.google.com/app/apikey).

```bash
cd Threat-Detector-Backend
./mvnw spring-boot:run
```
L'API démarre sur `http://localhost:8080`.

**Frontend**
```bash
cd Threat-Detector-Front
npm install
ng serve
```
L'app est accessible sur `http://localhost:4200`.

---

Projet réalisé par Salma Bentisse dans le cadre d'un mémoire de Master, octobre 2026.

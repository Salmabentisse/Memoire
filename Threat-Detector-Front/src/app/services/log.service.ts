import { Injectable, signal } from '@angular/core';
import { CompareResult } from '../models/log.model';

/**
 * Service qui fait le lien entre le frontend et le backend Spring Boot.
 * Il envoie le fichier CSV au backend et stocke le résultat de l'analyse.
 * Le résultat est stocké dans un signal Angular pour être réactif.
 */
@Injectable({ providedIn: 'root' })
export class LogService {

  // URL du backend — Spring Boot tourne en local sur le port 8080
  private readonly apiUrl = 'http://localhost:8080/analyze';

  // Signal Angular qui contient le résultat de la dernière analyse
  // null = pas encore analysé, sinon contient les alertes et métriques
  readonly result = signal<CompareResult | null>(null);

  // true pendant l'appel à Gemini — utilisé par la topbar pour informer l'utilisateur
  readonly isAnalyzing = signal<boolean>(false);

  /**
   * Envoie le fichier CSV au backend et retourne le résultat de l'analyse.
   * Utilise fetch() avec un timeout de 150 secondes car Gemini peut être lent.
   *
   * @param file fichier CSV sélectionné par l'utilisateur
   * @returns résultat de l'analyse (alertes règles + alertes IA + métriques)
   */
  async analyzeFile(file: File): Promise<CompareResult> {
    // On construit le FormData avec le fichier à envoyer
    const formData = new FormData();
    formData.append('file', file);

    // AbortController permet d'annuler la requête si elle dépasse le timeout
    const ctrl = new AbortController();
    const tid = window.setTimeout(() => ctrl.abort(), 150_000); // 150 secondes max

    const res = await fetch(this.apiUrl, {
      method: 'POST',
      body: formData,
      signal: ctrl.signal
    });

    // On annule le timer puisque la requête est terminée
    window.clearTimeout(tid);

    // Si le backend retourne une erreur HTTP, on lance une exception
    if (!res.ok) {
      throw new Error(`Erreur serveur : ${res.status}`);
    }

    // On convertit la réponse JSON en objet TypeScript
    return await res.json() as CompareResult;
  }

  /**
   * Stocke le résultat de l'analyse dans le signal.
   * Le dashboard se met à jour automatiquement grâce à la réactivité des signals.
   */
  setResult(data: CompareResult): void {
    this.result.set(data);
  }
}

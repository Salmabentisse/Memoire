import { Component, Input } from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { MatTabsModule } from '@angular/material/tabs';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LogService } from '../../services/log.service';
import { LlmAlert } from '../../models/log.model';

/**
 * Composant qui affiche les résultats de l'analyse.
 * Il récupère les données depuis le LogService et les affiche sous forme de tableau de bord.
 */
@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, DecimalPipe, MatTabsModule, MatIconModule, MatTooltipModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css',
})
export class DashboardComponent {

  // Onglet actif passé depuis app.ts via la sidebar (0=Règles, 1=IA, 2=Comparaison)
  @Input() activeTab: number = 0;

  constructor(public logService: LogService) {}

  /**
   * Retourne le résultat de l'analyse en cours (ou null si pas encore analysé).
   */
  result() {
    return this.logService.result();
  }

  /**
   * Retourne les alertes IA qui n'ont pas été détectées par les règles classiques.
   * Ce sont les menaces "exclusives" à l'IA — celles que les règles ont ratées.
   */
  exclusiveAiAlerts(): LlmAlert[] {
    const r = this.result();
    if (!r) return [];

    // On collecte tous les numéros de lignes déjà couverts par les règles classiques
    const ruleRows: number[] = [];
    for (const alert of r.ruleAlerts) {
      ruleRows.push(alert.row);
    }

    // On filtre les alertes IA pour ne garder que celles hors règles
    const exclusive: LlmAlert[] = [];
    for (const alert of r.llmAlerts) {
      if (!ruleRows.includes(alert.row)) {
        exclusive.push(alert);
      }
    }

    return exclusive;
  }

  /**
   * Calcule la distribution des scores de confiance des alertes IA.
   * Retourne le nombre d'alertes par catégorie : haute (≥75%), moyenne (50-74%), faible (<50%).
   */
  confDistribution() {
    const r = this.result();
    if (!r) return { high: 0, medium: 0, low: 0, total: 1 };

    let high = 0;
    let medium = 0;
    let low = 0;

    for (const alert of r.llmAlerts) {
      if (alert.confidence >= 75) {
        high++;
      } else if (alert.confidence >= 50) {
        medium++;
      } else {
        low++;
      }
    }

    // On utilise 1 comme minimum pour éviter une division par zéro dans le template
    const total = r.llmAlerts.length > 0 ? r.llmAlerts.length : 1;
    return { high, medium, low, total };
  }

  /**
   * Vérifie si une alerte IA sur une ligne donnée n'existe pas dans les alertes classiques.
   * Utilisé dans le template pour afficher le badge "Hors règles".
   */
  isExclusive(row: number): boolean {
    const r = this.result();
    if (!r) return false;

    for (const alert of r.ruleAlerts) {
      if (alert.row === row) return false; // ligne déjà détectée par les règles
    }

    return true; // ligne non couverte par les règles → exclusive à l'IA
  }

  /**
   * Retourne la classe CSS à appliquer selon le score de confiance.
   * Utilisé pour colorier la barre de confiance (vert/orange/rouge).
   */
  confidenceClass(value: number): string {
    if (value >= 75) return 'conf-high';   // vert
    if (value >= 50) return 'conf-medium'; // orange
    return 'conf-low';                     // rouge
  }
}

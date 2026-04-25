import { Component, inject, signal } from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { UploadComponent } from './components/upload/upload.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { LogService } from './services/log.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, DecimalPipe, MatIconModule, MatTooltipModule, UploadComponent, DashboardComponent],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  readonly logService = inject(LogService);

  // Onglet actif du dashboard : 0 = Règles, 1 = IA, 2 = Comparaison
  // Partagé entre la sidebar et le composant dashboard
  activeTab = signal<number>(0);

  /**
   * Appelé par les liens de la sidebar.
   * Change l'onglet actif et scrolle vers le panel résultats si besoin.
   */
  goToTab(index: number): void {
    this.activeTab.set(index);
    const el = document.getElementById('results-section');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  /**
   * Réinitialise le résultat pour permettre une nouvelle analyse.
   */
  newAnalysis(): void {
    this.logService.result.set(null);
    this.activeTab.set(0);
  }
}

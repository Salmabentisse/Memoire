import { Component, ElementRef, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { LogService } from '../../services/log.service';

// Nombre de lignes à afficher dans l'aperçu du CSV
const PREVIEW_ROWS = 8;

// Interface qui représente l'aperçu du fichier CSV avant analyse
export interface CsvPreview {
  headers: string[];   // noms des colonnes
  rows: string[][];    // premières lignes de données
  totalRows: number;   // nombre total de lignes dans le fichier
}

/**
 * Composant qui gère l'upload du fichier CSV.
 * Il permet de glisser-déposer un fichier ou de le sélectionner via l'explorateur.
 * Il affiche un aperçu du contenu avant de lancer l'analyse.
 */
@Component({
  selector: 'app-upload',
  standalone: true,
  imports: [CommonModule, MatButtonModule, MatIconModule],
  templateUrl: './upload.component.html',
  styleUrl: './upload.component.css',
})
export class UploadComponent {

  // Référence vers l'input file caché dans le template HTML
  @ViewChild('fileInput') fileInput!: ElementRef<HTMLInputElement>;

  // État du composant
  selectedFile: File | null = null;  // fichier sélectionné par l'utilisateur
  isDragging = false;                // true quand l'utilisateur glisse un fichier sur la zone
  isLoading = false;                 // true pendant l'appel à l'API backend
  error: string | null = null;       // message d'erreur affiché à l'utilisateur
  preview: CsvPreview | null = null; // aperçu des premières lignes du CSV

  // Injection du service qui communique avec le backend
  constructor(private logService: LogService) {}

  /**
   * Empêche le comportement par défaut du navigateur (ouvrir le fichier)
   * et indique visuellement que le drag est actif.
   */
  onDragOver(event: DragEvent): void {
    event.preventDefault();
    this.isDragging = true;
  }

  /**
   * Désactive l'indicateur de drag quand la souris quitte la zone.
   */
  onDragLeave(event: DragEvent): void {
    event.preventDefault();
    this.isDragging = false;
  }

  /**
   * Récupère le fichier déposé et le traite.
   */
  onDrop(event: DragEvent): void {
    event.preventDefault();
    this.isDragging = false;

    // On récupère le premier fichier déposé
    const file = event.dataTransfer?.files?.[0];
    if (file) {
      this.handleFile(file);
    }
  }

  /**
   * Récupère le fichier sélectionné via l'explorateur de fichiers.
   */
  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) {
      this.handleFile(file);
    }
  }

  /**
   * Vérifie que le fichier est bien un CSV puis lance l'aperçu.
   */
  private handleFile(file: File): void {
    this.error = null;
    this.preview = null;

    // On vérifie l'extension du fichier
    if (!file.name.toLowerCase().endsWith('.csv')) {
      this.error = 'Seuls les fichiers .csv sont acceptés.';
      return;
    }

    this.selectedFile = file;
    this.parseCsvPreview(file); // on génère l'aperçu immédiatement
  }

  /**
   * Lit les premières lignes du CSV et génère l'aperçu affiché à l'utilisateur.
   * On lit seulement les 65 536 premiers octets pour ne pas surcharger le navigateur.
   */
  private parseCsvPreview(file: File): void {
    const reader = new FileReader();

    reader.onload = (event) => {
      const text = event.target?.result as string;

      // On sépare le texte en lignes et on ignore les lignes vides
      const lines = text.split('\n').filter(line => line.trim().length > 0);

      if (lines.length < 2) return; // fichier trop court ou vide

      // La première ligne contient les noms des colonnes
      const headers = this.parseCsvLine(lines[0]);

      // Les lignes suivantes contiennent les données
      const dataLines = lines.slice(1);
      const previewRows: string[][] = [];

      // On parse seulement les premières lignes pour l'aperçu
      for (let i = 0; i < Math.min(PREVIEW_ROWS, dataLines.length); i++) {
        previewRows.push(this.parseCsvLine(dataLines[i]));
      }

      this.preview = {
        headers: headers,
        rows: previewRows,
        totalRows: dataLines.length
      };
    };

    reader.readAsText(file.slice(0, 65536));
  }

  /**
   * Découpe une ligne CSV en tableau de valeurs.
   * Gère les guillemets pour les valeurs qui contiennent des virgules.
   * Exemple : 'a,"b,c",d' → ['a', 'b,c', 'd']
   */
  private parseCsvLine(line: string): string[] {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;

    for (const ch of line) {
      if (ch === '"') {
        inQuotes = !inQuotes; // on entre ou sort des guillemets
      } else if (ch === ',' && !inQuotes) {
        result.push(current.trim()); // fin d'une valeur
        current = '';
      } else {
        current += ch; // on accumule les caractères
      }
    }

    result.push(current.trim()); // dernière valeur de la ligne
    return result;
  }

  /**
   * Ouvre l'explorateur de fichiers natif du navigateur.
   */
  openFilePicker(): void {
    this.fileInput.nativeElement.value = ''; // reset pour pouvoir re-sélectionner le même fichier
    this.fileInput.nativeElement.click();
  }

  /**
   * Formate une taille en octets en une chaîne lisible (ex: 1.5 Mo).
   */
  formatSize(bytes: number): string {
    if (bytes < 1024) return bytes + ' o';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' Ko';
    return (bytes / (1024 * 1024)).toFixed(1) + ' Mo';
  }

  /**
   * Réinitialise le composant pour permettre un nouvel upload.
   */
  reset(): void {
    this.selectedFile = null;
    this.preview = null;
    this.error = null;
    this.fileInput.nativeElement.value = '';
  }

  /**
   * Lance l'analyse du fichier CSV en appelant le backend.
   * Utilise async/await pour attendre la réponse sans bloquer l'interface.
   */
  async analyse(): Promise<void> {
    if (!this.selectedFile || this.isLoading) return;

    this.isLoading = true;
    this.error = null;

    // On informe la topbar que Gemini est en cours d'appel
    this.logService.isAnalyzing.set(true);

    try {
      // Appel au backend — peut prendre jusqu'à 2 minutes à cause de Gemini
      const result = await this.logService.analyzeFile(this.selectedFile);

      // On stocke le résultat dans le service pour que le dashboard puisse l'afficher
      this.logService.setResult(result);

    } catch (err) {
      this.error = "Erreur lors de l'analyse. Vérifiez que le serveur est démarré.";
      console.error(err);
    } finally {
      // Dans tous les cas (succès ou erreur), on remet les états à false
      this.isLoading = false;
      this.logService.isAnalyzing.set(false);
    }
  }
}

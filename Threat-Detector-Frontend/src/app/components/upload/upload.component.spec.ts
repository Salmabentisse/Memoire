import { TestBed } from '@angular/core/testing';
import { UploadComponent } from './upload.component';
import { LogService } from '../../services/log.service';
import { signal } from '@angular/core';

describe('UploadComponent', () => {
  let component: UploadComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UploadComponent],
      providers: [{
        provide: LogService,
        useValue: {
          result: signal(null),
          isAnalyzing: signal(false),
          analyzeFile: vi.fn(),
          setResult: vi.fn(),
        },
      }],
    }).compileComponents();

    const fixture = TestBed.createComponent(UploadComponent);
    component = fixture.componentInstance;
  });

  // ── formatSize ───────────────────────────────────────────────

  it('formatSize formats bytes', () => {
    expect(component.formatSize(512)).toBe('512 o');
  });

  it('formatSize formats kilobytes', () => {
    expect(component.formatSize(2048)).toBe('2.0 Ko');
  });

  it('formatSize formats megabytes', () => {
    expect(component.formatSize(3 * 1024 * 1024)).toBe('3.0 Mo');
  });

  // ── handleFile via onFileSelected ────────────────────────────

  it('rejects non-CSV file and sets error', () => {
    const file = new File(['data'], 'test.txt', { type: 'text/plain' });
    const event = { target: { files: [file] } } as unknown as Event;
    component.onFileSelected(event);
    expect(component.error).toContain('.csv');
    expect(component.selectedFile).toBeNull();
  });

  it('accepts CSV file and clears error', () => {
    const file = new File(['col\nval'], 'data.csv', { type: 'text/csv' });
    const event = { target: { files: [file] } } as unknown as Event;
    component.onFileSelected(event);
    expect(component.error).toBeNull();
    expect(component.selectedFile).toBe(file);
  });

  // ── reset ─────────────────────────────────────────────────────

  it('reset clears selectedFile, preview and error', () => {
    // Charge un fichier d'abord
    const file = new File(['col\nval'], 'data.csv', { type: 'text/csv' });
    component.selectedFile = file;
    component.error = 'une erreur';

    // Simule un input file pour que reset() puisse accéder à nativeElement
    const inputEl = document.createElement('input');
    (component as any).fileInput = { nativeElement: inputEl };

    component.reset();

    expect(component.selectedFile).toBeNull();
    expect(component.error).toBeNull();
    expect(component.preview).toBeNull();
  });

  // ── analyse ───────────────────────────────────────────────────

  it('analyse sets isLoading to true during call', async () => {
    const logService = TestBed.inject(LogService);
    let capturedIsAnalyzing = false;

    (logService.analyzeFile as ReturnType<typeof vi.fn>).mockImplementation(() => {
      capturedIsAnalyzing = component.isLoading;
      return Promise.resolve({ ruleAlerts: [], llmAlerts: [], metrics: { totalRows: 0, ruleTruePositives: 0, ruleFalsePositives: 0, llmTruePositives: 0, llmFalsePositives: 0, llmAvgConfidence: 0 } });
    });

    component.selectedFile = new File(['col\nval'], 'data.csv', { type: 'text/csv' });
    await component.analyse();

    expect(capturedIsAnalyzing).toBe(true);
    expect(component.isLoading).toBe(false);
  });

  it('analyse sets error on failure', async () => {
    const logService = TestBed.inject(LogService);
    (logService.analyzeFile as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network error'));

    component.selectedFile = new File(['col\nval'], 'data.csv', { type: 'text/csv' });
    await component.analyse();

    expect(component.error).toBeTruthy();
    expect(component.isLoading).toBe(false);
  });
});

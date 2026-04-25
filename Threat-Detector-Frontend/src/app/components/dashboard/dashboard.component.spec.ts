import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { DashboardComponent } from './dashboard.component';
import { LogService } from '../../services/log.service';
import { CompareResult, LlmAlert } from '../../models/log.model';

const llmAlert = (row: number, confidence: number, severity: 'LOW' | 'MEDIUM' | 'HIGH' = 'HIGH'): LlmAlert => ({
  row, threatType: 'Test', severity, explanation: 'e', recommendation: 'r',
  confidence, sourceIp: '1.1.1.1', destIp: '2.2.2.2', srcPort: 0, dstPort: 80, protocol: 'TCP',
});

const makeResult = (overrides: Partial<CompareResult> = {}): CompareResult => ({
  ruleAlerts: [
    { row: 1, rule: 'PORT_SCAN_DETECTED', severity: 'HIGH',   description: 'desc' },
    { row: 2, rule: 'DDOS_SYN_FLOOD',     severity: 'MEDIUM', description: 'desc' },
  ],
  llmAlerts: [
    llmAlert(1, 90, 'HIGH'),
    llmAlert(3, 60, 'MEDIUM'),
    llmAlert(4, 30, 'LOW'),
  ],
  metrics: { totalRows: 100, llmAvgConfidence: 60 },
  ...overrides,
});

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let resultSignal: ReturnType<typeof signal<CompareResult | null>>;

  beforeEach(() => {
    resultSignal = signal<CompareResult | null>(null);

    TestBed.configureTestingModule({
      imports: [DashboardComponent],
      providers: [{
        provide: LogService,
        useValue: { result: resultSignal, isAnalyzing: signal(false) },
      }],
    });

    const fixture = TestBed.createComponent(DashboardComponent);
    component = fixture.componentInstance;
  });

  // ── result() ─────────────────────────────────────────────────

  it('result() returns null initially', () => {
    expect(component.result()).toBeNull();
  });

  it('result() reflects signal changes', () => {
    resultSignal.set(makeResult());
    expect(component.result()).not.toBeNull();
    expect(component.result()!.ruleAlerts).toHaveLength(2);
  });

  // ── confDistribution() ───────────────────────────────────────

  it('confDistribution returns zeros when result is null', () => {
    const d = component.confDistribution();
    expect(d.high).toBe(0);
    expect(d.medium).toBe(0);
    expect(d.low).toBe(0);
  });

  it('confDistribution buckets alerts by threshold', () => {
    resultSignal.set(makeResult());
    // confidence 90 → high (≥75), 60 → medium (50-74), 30 → low (<50)
    const d = component.confDistribution();
    expect(d.high).toBe(1);
    expect(d.medium).toBe(1);
    expect(d.low).toBe(1);
  });

  it('confDistribution handles all alerts in one bucket', () => {
    resultSignal.set(makeResult({
      llmAlerts: [llmAlert(1, 80), llmAlert(2, 90), llmAlert(3, 76)],
    }));
    const d = component.confDistribution();
    expect(d.high).toBe(3);
    expect(d.medium).toBe(0);
    expect(d.low).toBe(0);
  });

  // ── exclusiveAiAlerts() ──────────────────────────────────────

  it('exclusiveAiAlerts returns empty when result is null', () => {
    expect(component.exclusiveAiAlerts()).toHaveLength(0);
  });

  it('exclusiveAiAlerts returns only alerts not in rule rows', () => {
    resultSignal.set(makeResult());
    // ruleAlerts rows = {1, 2} ; llmAlerts rows = {1, 3, 4}
    // exclusifs = rows 3 et 4
    const exclusive = component.exclusiveAiAlerts();
    expect(exclusive).toHaveLength(2);
    expect(exclusive.map(a => a.row)).toEqual(expect.arrayContaining([3, 4]));
  });

  it('exclusiveAiAlerts returns all llm alerts when no rule alerts', () => {
    resultSignal.set(makeResult({ ruleAlerts: [] }));
    expect(component.exclusiveAiAlerts()).toHaveLength(3);
  });

  it('exclusiveAiAlerts returns empty when all llm rows are covered by rules', () => {
    resultSignal.set(makeResult({
      llmAlerts: [llmAlert(1, 80), llmAlert(2, 70)],
    }));
    expect(component.exclusiveAiAlerts()).toHaveLength(0);
  });

  // ── isExclusive() ─────────────────────────────────────────────

  it('isExclusive returns false when result is null', () => {
    expect(component.isExclusive(1)).toBe(false);
  });

  it('isExclusive returns false when row is in rule alerts', () => {
    resultSignal.set(makeResult());
    expect(component.isExclusive(1)).toBe(false);
  });

  it('isExclusive returns true when row is only in llm alerts', () => {
    resultSignal.set(makeResult());
    expect(component.isExclusive(3)).toBe(true);
  });

  // ── confidenceClass() ─────────────────────────────────────────

  it('confidenceClass returns conf-high for >= 75', () => {
    expect(component.confidenceClass(75)).toBe('conf-high');
    expect(component.confidenceClass(100)).toBe('conf-high');
  });

  it('confidenceClass returns conf-medium for 50-74', () => {
    expect(component.confidenceClass(50)).toBe('conf-medium');
    expect(component.confidenceClass(74)).toBe('conf-medium');
  });

  it('confidenceClass returns conf-low for < 50', () => {
    expect(component.confidenceClass(49)).toBe('conf-low');
    expect(component.confidenceClass(0)).toBe('conf-low');
  });
});

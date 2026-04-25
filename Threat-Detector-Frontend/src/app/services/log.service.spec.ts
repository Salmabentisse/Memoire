import { TestBed } from '@angular/core/testing';
import { LogService } from './log.service';
import { CompareResult } from '../models/log.model';

const mockResult: CompareResult = {
  ruleAlerts: [{ row: 1, rule: 'PORT_SCAN_DETECTED', severity: 'HIGH', description: 'desc' }],
  llmAlerts: [{
    row: 1, threatType: 'Port Scan', severity: 'HIGH',
    explanation: 'expl', recommendation: 'reco', confidence: 90,
    sourceIp: '1.1.1.1', destIp: '2.2.2.2', srcPort: 12345, dstPort: 80, protocol: 'TCP',
  }],
  metrics: { totalRows: 10, llmAvgConfidence: 90 },
};

describe('LogService', () => {
  let service: LogService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(LogService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('result signal starts as null', () => {
    expect(service.result()).toBeNull();
  });

  it('isAnalyzing signal starts as false', () => {
    expect(service.isAnalyzing()).toBe(false);
  });

  it('setResult updates the result signal', () => {
    service.setResult(mockResult);
    expect(service.result()).toEqual(mockResult);
  });

  it('setResult can be called multiple times', () => {
    service.setResult(mockResult);
    const updated = { ...mockResult, ruleAlerts: [] };
    service.setResult(updated);
    expect(service.result()!.ruleAlerts).toHaveLength(0);
  });

  it('analyzeFile throws on HTTP error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    const file = new File(['col\nval'], 'test.csv', { type: 'text/csv' });
    await expect(service.analyzeFile(file)).rejects.toThrow('Erreur serveur : 500');
    vi.unstubAllGlobals();
  });

  it('analyzeFile returns parsed result on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue(mockResult),
    }));
    const file = new File(['col\nval'], 'test.csv', { type: 'text/csv' });
    const result = await service.analyzeFile(file);
    expect(result).toEqual(mockResult);
    vi.unstubAllGlobals();
  });
});

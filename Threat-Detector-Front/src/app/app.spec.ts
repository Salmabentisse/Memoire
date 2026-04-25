import { TestBed } from '@angular/core/testing';
import { App } from './app';

describe('App', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
    }).compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should have a header element', () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    const header = fixture.nativeElement.querySelector('header');
    expect(header).not.toBeNull();
  });
});

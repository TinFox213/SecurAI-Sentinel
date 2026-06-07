# Scan History and Reporting

## Purpose

Scan History and Reporting gives users persistent local scan records, reloadable analysis, and exportable PDF reports.

## Source Files

- `App.tsx`
- `src/components/layout/Sidebar.tsx`
- `src/services/db.ts`
- `src/services/reportGenerator.ts`

## What It Does Today

- Saves legacy AI scan results to `scanHistory`.
- Sidebar can expand History and Trends and load previous scans.
- Sidebar can delete individual historical scans.
- `App.tsx` can export the current analysis as a PDF security assessment report.
- Report generator includes executive summary, threat level, risk score, detailed analysis, recommendations, exploitation vector, exploitability metrics, visual risk gauge, and footer.

## Data and API Dependencies

- IndexedDB: `scanHistory`
- jsPDF, html2canvas, jspdf-autotable

## Limitations

- History is local-browser only.
- Report export is focused on legacy `SecurityAnalysis` objects, not every module's richer data.
- Some report text contains encoding artifacts for warning symbols.

## Real-Tool Upgrade Path

Create a unified report model for all normalized findings and tool artifacts. Add report templates for executive, technical, DFIR, compliance, and red-team engagements.


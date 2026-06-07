import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { SecurityAnalysis, ScanType, ThreatLevel } from '../types/types';

interface ReportData {
  scanType: ScanType;
  timestamp: Date;
  analysis: SecurityAnalysis;
  rawData?: string;
}

export const generatePDF = async (data: ReportData): Promise<void> => {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let yPos = 20;

  // Helper function to add new page if needed
  const checkPageBreak = (requiredSpace: number) => {
    if (yPos + requiredSpace > pageHeight - 20) {
      doc.addPage();
      yPos = 20;
    }
  };

  // Header
  doc.setFillColor(6, 182, 212);
  doc.rect(0, 0, pageWidth, 35, 'F');
  
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text('SecurAI Sentinel', 15, 15);
  
  doc.setFontSize(12);
  doc.setFont('helvetica', 'normal');
  doc.text('Security Assessment Report', 15, 25);
  
  doc.setTextColor(200, 200, 200);
  doc.setFontSize(9);
  doc.text(`Generated: ${data.timestamp.toLocaleString()}`, 15, 32);

  yPos = 45;

  // Report Info Section
  doc.setTextColor(0, 0, 0);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text('Report Information', 15, yPos);
  yPos += 10;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  
  const infoData = [
    ['Scan Type:', data.scanType],
    ['Date:', data.timestamp.toLocaleDateString()],
    ['Time:', data.timestamp.toLocaleTimeString()],
  ];

  autoTable(doc, {
    startY: yPos,
    head: [],
    body: infoData,
    theme: 'plain',
    styles: { fontSize: 10, cellPadding: 2 },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 40 },
      1: { cellWidth: 'auto' },
    },
  });

  yPos = (doc as any).lastAutoTable.finalY + 15;

  // Executive Summary Section
  checkPageBreak(40);
  
  // Threat Level Badge
  const threatColors = {
    [ThreatLevel.CRITICAL]: [239, 68, 68],
    [ThreatLevel.HIGH]: [249, 115, 22],
    [ThreatLevel.MEDIUM]: [234, 179, 8],
    [ThreatLevel.LOW]: [16, 185, 129],
  };

  const [r, g, b] = threatColors[data.analysis.threat_level] || [100, 100, 100];
  
  doc.setFillColor(r, g, b);
  doc.roundedRect(15, yPos, 50, 15, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text(data.analysis.threat_level, 40, yPos + 10, { align: 'center' });

  // Risk Score
  doc.setFillColor(220, 220, 220);
  doc.roundedRect(70, yPos, 50, 15, 3, 3, 'F');
  doc.setTextColor(0, 0, 0);
  doc.text(`Risk: ${data.analysis.risk_score}/100`, 95, yPos + 10, { align: 'center' });

  yPos += 25;

  // Summary
  doc.setTextColor(0, 0, 0);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('Executive Summary', 15, yPos);
  yPos += 8;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  const summaryLines = doc.splitTextToSize(data.analysis.summary, pageWidth - 30);
  summaryLines.forEach((line: string) => {
    checkPageBreak(7);
    doc.text(line, 15, yPos);
    yPos += 7;
  });

  yPos += 10;

  // Detailed Analysis Section
  checkPageBreak(20);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('Technical Analysis', 15, yPos);
  yPos += 8;

  doc.setFontSize(9);
  doc.setFont('courier', 'normal');
  const analysisLines = doc.splitTextToSize(data.analysis.detailed_analysis, pageWidth - 30);
  analysisLines.forEach((line: string) => {
    checkPageBreak(6);
    doc.text(line, 15, yPos);
    yPos += 6;
  });

  yPos += 10;

  // Recommendations Section
  checkPageBreak(30);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('Remediation Recommendations', 15, yPos);
  yPos += 10;

  const recommendationsData = data.analysis.recommendations.map((rec, index) => [
    `${index + 1}`,
    rec,
  ]);

  autoTable(doc, {
    startY: yPos,
    head: [['#', 'Recommendation']],
    body: recommendationsData,
    theme: 'striped',
    headStyles: { fillColor: [6, 182, 212], textColor: [255, 255, 255] },
    styles: { fontSize: 9 },
    columnStyles: {
      0: { cellWidth: 10, halign: 'center' },
      1: { cellWidth: 'auto' },
    },
  });

  yPos = (doc as any).lastAutoTable.finalY + 15;

  // Exploitation Vector Section
  checkPageBreak(30);
  doc.setFillColor(254, 226, 226);
  doc.rect(15, yPos, pageWidth - 30, 5, 'F');
  
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(220, 38, 38);
  doc.text('⚠ EXPLOITATION VECTOR', 17, yPos + 3.5);
  yPos += 10;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(0, 0, 0);
  const exploitLines = doc.splitTextToSize(data.analysis.additional_notes, pageWidth - 30);
  exploitLines.forEach((line: string) => {
    checkPageBreak(6);
    doc.text(line, 15, yPos);
    yPos += 6;
  });

  // Footer
  const totalPages = doc.internal.pages.length - 1;
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.setFont('helvetica', 'normal');
    doc.text(
      `SecurAI Sentinel v2.0 | Page ${i} of ${totalPages}`,
      pageWidth / 2,
      pageHeight - 10,
      { align: 'center' }
    );
    doc.text(
      'CONFIDENTIAL - Internal Use Only',
      pageWidth - 15,
      pageHeight - 10,
      { align: 'right' }
    );
  }

  // Save the PDF
  const fileName = `SecurAI_${data.scanType.replace(/\s+/g, '_')}_${data.timestamp.getTime()}.pdf`;
  doc.save(fileName);
};

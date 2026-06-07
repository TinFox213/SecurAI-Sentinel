import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Wrench, 
  Code2, 
  Image, 
  ShieldAlert, 
  Binary,
  Loader2,
  CheckCircle,
  XCircle,
  AlertTriangle,
  MapPin,
  Download,
  Sparkles,
  Copy,
  ArrowRight,
  Info
} from 'lucide-react';
import EXIF from 'exif-js';
import { analyzeSecurityData } from '../../services/geminiService';
import { ScanType } from '../../types/types';
import { toast } from 'react-hot-toast';

type TabType = 'web3' | 'exif' | 'breach' | 'decoder';

interface Web3Vulnerability {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  type: string;
  description: string;
  location?: string;
}

interface Web3AuditReport {
  vulnerabilities: Web3Vulnerability[];
  gasOptimizations: string[];
  securityScore: number;
}

interface EXIFData {
  gpsLatitude?: number;
  gpsLongitude?: number;
  make?: string;
  model?: string;
  dateTime?: string;
  [key: string]: any;
}

interface BreachData {
  breaches: Array<{
    year: string;
    name: string;
    severity: string;
  }>;
  riskLevel: string;
  recommendations: string[];
}

export default function UtilityBelt() {
  const [activeTab, setActiveTab] = useState<TabType>('web3');

  // ========================================
  // MODULE A: Web3 Smart Contract Auditor
  // ========================================
  const [solidityCode, setSolidityCode] = useState('');
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditReport, setAuditReport] = useState<Web3AuditReport | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  const runWeb3Audit = async () => {
    if (!solidityCode.trim()) return;

    setAuditLoading(true);
    setAuditError(null);
    setAuditReport(null);

    try {
      const prompt = `You are a Smart Contract Security Auditor specializing in Solidity.

Analyze this Solidity code for vulnerabilities and gas optimization opportunities.

Focus on:
1. Reentrancy attacks (check for checks-effects-interactions pattern)
2. Integer overflow/underflow (pre-Solidity 0.8.0 concerns)
3. Access control issues
4. Gas limit and optimization issues
5. Unchecked external calls
6. Front-running vulnerabilities

CODE TO AUDIT:
\`\`\`solidity
${solidityCode}
\`\`\`

Return a JSON object with this exact structure:
{
  "vulnerabilities": [
    {
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "type": "Vulnerability Type",
      "description": "Detailed description",
      "location": "Function or line reference"
    }
  ],
  "gasOptimizations": ["tip1", "tip2", ...],
  "securityScore": 0-100
}`;

      const response = await analyzeSecurityData(ScanType.GENERAL_LOG, prompt);
      
      // Try to parse JSON from response
      let reportData: Web3AuditReport;
      try {
        // Extract JSON from markdown code blocks if present
        const jsonMatch = response.detailed_analysis.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/);
        if (jsonMatch) {
          reportData = JSON.parse(jsonMatch[1]);
        } else {
          reportData = JSON.parse(response.detailed_analysis);
        }
      } catch (parseError) {
        // If JSON parsing fails, create a structured response from the text
        reportData = {
          vulnerabilities: [{
            severity: 'MEDIUM',
            type: 'Manual Review Required',
            description: response.detailed_analysis.substring(0, 500),
            location: 'See full analysis'
          }],
          gasOptimizations: ['Review AI response for optimization suggestions'],
          securityScore: 50
        };
      }

      setAuditReport(reportData);
    } catch (error: any) {
      console.error('Web3 Audit Error:', error);
      setAuditError(error.message || 'Audit failed');
    } finally {
      setAuditLoading(false);
    }
  };

  const loadSampleContract = () => {
    setSolidityCode(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: Reentrancy attack possible
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update (BAD)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // State update after external call
    }
    
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}`);
  };

  const loadSampleExif = () => {
    const dummyDataUrl = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
    setImagePreview(dummyDataUrl);
    setSelectedImage(new File([new Blob()], "sample_iphone_photo.jpg", { type: "image/jpeg" }));
    setExifData({
      make: 'Apple',
      model: 'iPhone 15 Pro Max',
      dateTime: '2026:05:14 12:34:56',
      gpsLatitude: 37.774929,
      gpsLongitude: -122.419418
    });
    toast.success('Sample iPhone photo metadata loaded');
  };

  const loadSampleBreach = () => {
    setBreachEmail('target-officer@yahoo.com');
    toast.success('Sample email loaded. Click "Check Breaches" to query.');
  };

  const loadSampleDecoder = () => {
    setDecoderInput('U2VjdXJCSSBTZW50aW5lbCBVdGlsaXR5IEJlbHQgRmVhdHVyZQ==');
    toast.success('Sample Base64 encoded payload loaded. Click "← Base64" to decode.');
  };

  // ========================================
  // MODULE B: EXIF Ghost Cleaner
  // ========================================
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [exifData, setExifData] = useState<EXIFData | null>(null);
  const [exifLoading, setExifLoading] = useState(false);

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedImage(file);
    setExifData(null);
    setExifLoading(true);

    // Create preview
    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target?.result as string;
      setImagePreview(dataUrl);

      // Extract EXIF data
      const img = document.createElement('img');
      img.onload = () => {
        EXIF.getData(img as any, function(this: any) {
          const data: EXIFData = {};
          
          // Extract common EXIF tags
          const allTags = EXIF.getAllTags(this);
          
          if (allTags) {
            data.make = allTags.Make;
            data.model = allTags.Model;
            data.dateTime = allTags.DateTime;
            
            // GPS data
            const lat = allTags.GPSLatitude;
            const latRef = allTags.GPSLatitudeRef;
            const lon = allTags.GPSLongitude;
            const lonRef = allTags.GPSLongitudeRef;
            
            if (lat && lon) {
              // Convert to decimal degrees
              data.gpsLatitude = convertDMSToDD(lat, latRef);
              data.gpsLongitude = convertDMSToDD(lon, lonRef);
            }
          }
          
          setExifData(Object.keys(data).length > 0 ? data : null);
          setExifLoading(false);
        });
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  const convertDMSToDD = (dms: number[], ref: string): number => {
    const decimal = dms[0] + dms[1] / 60 + dms[2] / 3600;
    return (ref === 'S' || ref === 'W') ? -decimal : decimal;
  };

  const sanitizeAndDownload = () => {
    if (!imagePreview || !selectedImage) return;

    const img = document.createElement('img');
    img.onload = () => {
      // Create canvas and draw image (this strips EXIF)
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx?.drawImage(img, 0, 0);

      // Convert to blob and download
      canvas.toBlob((blob) => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sanitized_${selectedImage.name}`;
        a.click();
        URL.revokeObjectURL(url);
      }, 'image/jpeg', 0.95);
    };
    img.src = imagePreview;
  };

  // ========================================
  // MODULE C: Breach Radar
  // ========================================
  const [breachEmail, setBreachEmail] = useState('');
  const [breachLoading, setBreachLoading] = useState(false);
  const [breachData, setBreachData] = useState<BreachData | null>(null);
  const [breachError, setBreachError] = useState<string | null>(null);

  const runBreachCheck = async () => {
    if (!breachEmail.trim()) return;

    setBreachLoading(true);
    setBreachError(null);
    setBreachData(null);

    try {
      const domain = breachEmail.split('@')[1] || breachEmail;
      
      const prompt = `You are a Cybersecurity Breach Intelligence Analyst.

Analyze the domain: ${domain}

Provide information about:
1. Major historical data breaches associated with this domain
2. Risk assessment based on the domain's security history
3. Recommendations for users with accounts on this domain

Return a JSON object with this structure:
{
  "breaches": [
    {
      "year": "2019",
      "name": "Breach Name",
      "severity": "HIGH" | "MEDIUM" | "LOW"
    }
  ],
  "riskLevel": "HIGH" | "MEDIUM" | "LOW",
  "recommendations": ["recommendation1", "recommendation2", ...]
}

If this is a well-known major service (Gmail, Yahoo, Microsoft, etc.), include their known breaches.
If it's a lesser-known domain, provide a general risk assessment.`;

      const response = await analyzeSecurityData(ScanType.GENERAL_LOG, prompt);
      
      // Parse JSON response
      let reportData: BreachData;
      try {
        const jsonMatch = response.detailed_analysis.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/);
        if (jsonMatch) {
          reportData = JSON.parse(jsonMatch[1]);
        } else {
          reportData = JSON.parse(response.detailed_analysis);
        }
      } catch (parseError) {
        reportData = {
          breaches: [],
          riskLevel: 'MEDIUM',
          recommendations: ['Enable two-factor authentication', 'Use a unique password', 'Monitor for suspicious activity']
        };
      }

      setBreachData(reportData);
    } catch (error: any) {
      console.error('Breach Check Error:', error);
      setBreachError(error.message || 'Breach check failed');
    } finally {
      setBreachLoading(false);
    }
  };

  // ========================================
  // MODULE D: Payload Decoder (CyberChef Lite)
  // ========================================
  const [decoderInput, setDecoderInput] = useState('');
  const [decoderOutput, setDecoderOutput] = useState('');
  const [decoderOperation, setDecoderOperation] = useState<string>('');

  const decodeOperations = {
    toBase64: (input: string) => btoa(input),
    fromBase64: (input: string) => {
      try {
        return atob(input);
      } catch {
        return 'Invalid Base64';
      }
    },
    toHex: (input: string) => Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' '),
    fromHex: (input: string) => {
      try {
        return input.split(/\s+/).map(h => String.fromCharCode(parseInt(h, 16))).join('');
      } catch {
        return 'Invalid Hex';
      }
    },
    urlEncode: (input: string) => encodeURIComponent(input),
    urlDecode: (input: string) => {
      try {
        return decodeURIComponent(input);
      } catch {
        return 'Invalid URL Encoding';
      }
    },
    rot13: (input: string) => {
      return input.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
    }
  };

  const applyOperation = (op: keyof typeof decodeOperations) => {
    setDecoderOperation(op);
    setDecoderOutput(decodeOperations[op](decoderInput));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const swapInputOutput = () => {
    const temp = decoderInput;
    setDecoderInput(decoderOutput);
    setDecoderOutput(temp);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-indigo-950/20 to-slate-950 p-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 
                          border border-indigo-500/30 backdrop-blur-sm">
            <Wrench className="w-8 h-8 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-4xl font-bold text-white">
              Utility Belt
            </h1>
            <p className="text-gray-400 mt-1">
              Privacy & Security Toolkit - Offline First
            </p>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
        <button
          onClick={() => setActiveTab('web3')}
          className={`px-6 py-3 rounded-xl font-semibold transition-all whitespace-nowrap
                      flex items-center gap-2 ${
            activeTab === 'web3'
              ? 'bg-gradient-to-r from-purple-500 to-pink-500 text-white shadow-lg'
              : 'bg-slate-800/50 text-gray-400 hover:bg-slate-800/70 border border-slate-700/50'
          }`}
        >
          <Code2 className="w-5 h-5" />
          Web3 Audit
        </button>
        
        <button
          onClick={() => setActiveTab('exif')}
          className={`px-6 py-3 rounded-xl font-semibold transition-all whitespace-nowrap
                      flex items-center gap-2 ${
            activeTab === 'exif'
              ? 'bg-gradient-to-r from-green-500 to-emerald-500 text-white shadow-lg'
              : 'bg-slate-800/50 text-gray-400 hover:bg-slate-800/70 border border-slate-700/50'
          }`}
        >
          <Image className="w-5 h-5" />
          EXIF Cleaner
        </button>
        
        <button
          onClick={() => setActiveTab('breach')}
          className={`px-6 py-3 rounded-xl font-semibold transition-all whitespace-nowrap
                      flex items-center gap-2 ${
            activeTab === 'breach'
              ? 'bg-gradient-to-r from-red-500 to-orange-500 text-white shadow-lg'
              : 'bg-slate-800/50 text-gray-400 hover:bg-slate-800/70 border border-slate-700/50'
          }`}
        >
          <ShieldAlert className="w-5 h-5" />
          Breach Radar
        </button>
        
        <button
          onClick={() => setActiveTab('decoder')}
          className={`px-6 py-3 rounded-xl font-semibold transition-all whitespace-nowrap
                      flex items-center gap-2 ${
            activeTab === 'decoder'
              ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg'
              : 'bg-slate-800/50 text-gray-400 hover:bg-slate-800/70 border border-slate-700/50'
          }`}
        >
          <Binary className="w-5 h-5" />
          Payload Decoder
        </button>
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        
        {/* ========================================
            MODULE A: WEB3 SMART CONTRACT AUDITOR
            ======================================== */}
        {activeTab === 'web3' && (
          <motion.div
            key="web3"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Code2 className="w-6 h-6 text-purple-400" />
                  <h2 className="text-2xl font-bold text-white">Smart Contract Security Auditor</h2>
                </div>
                <button
                  onClick={loadSampleContract}
                  className="text-sm text-purple-400 hover:text-purple-300 flex items-center gap-2 
                             px-3 py-1.5 rounded-lg border border-purple-500/30 hover:bg-purple-500/10 
                             transition-all"
                >
                  <Sparkles className="w-4 h-4" />
                  Load Sample
                </button>
              </div>

              {/* Code Editor */}
              <div className="mb-4">
                <textarea
                  value={solidityCode}
                  onChange={(e) => setSolidityCode(e.target.value)}
                  placeholder="Paste your Solidity contract code here..."
                  className="w-full h-96 bg-slate-950/80 text-green-400 font-mono text-sm p-4 
                             rounded-lg border border-slate-700/50 focus:border-purple-500/50 
                             focus:outline-none resize-none scrollbar-thin 
                             scrollbar-thumb-purple-500/30 scrollbar-track-slate-800/30"
                  disabled={auditLoading}
                />
              </div>

              {/* Audit Button */}
              <button
                onClick={runWeb3Audit}
                disabled={auditLoading || !solidityCode.trim()}
                className="w-full py-4 bg-gradient-to-r from-purple-500 to-pink-500 rounded-xl 
                           font-bold text-white hover:from-purple-600 hover:to-pink-600 
                           disabled:opacity-50 disabled:cursor-not-allowed transition-all 
                           flex items-center justify-center gap-2 shadow-lg"
              >
                {auditLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Running Security Audit...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-5 h-5" />
                    Audit Contract
                  </>
                )}
              </button>

              {/* Audit Results */}
              <AnimatePresence>
                {auditError && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="mt-6 bg-red-500/10 border border-red-500/50 rounded-lg p-4"
                  >
                    <div className="flex items-center gap-2 text-red-400">
                      <XCircle className="w-5 h-5" />
                      <span className="font-semibold">Audit Failed:</span>
                      <span className="text-sm">{auditError}</span>
                    </div>
                  </motion.div>
                )}

                {auditReport && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="mt-6 space-y-4"
                  >
                    {/* Security Score */}
                    <div className="bg-slate-800/50 rounded-xl p-6 border border-slate-700/50">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-xl font-bold text-white">Security Score</h3>
                        <div className={`text-5xl font-black ${
                          auditReport.securityScore >= 80 ? 'text-green-400' :
                          auditReport.securityScore >= 60 ? 'text-yellow-400' :
                          'text-red-400'
                        }`}>
                          {auditReport.securityScore}
                        </div>
                      </div>
                      <div className="w-full h-3 bg-slate-700/50 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${auditReport.securityScore}%` }}
                          transition={{ duration: 1, ease: "easeOut" }}
                          className={`h-full rounded-full ${
                            auditReport.securityScore >= 80 ? 'bg-gradient-to-r from-green-500 to-emerald-500' :
                            auditReport.securityScore >= 60 ? 'bg-gradient-to-r from-yellow-500 to-orange-500' :
                            'bg-gradient-to-r from-red-500 to-pink-500'
                          }`}
                        />
                      </div>
                    </div>

                    {/* Vulnerabilities */}
                    <div className="bg-slate-800/50 rounded-xl p-6 border border-slate-700/50">
                      <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                        Vulnerabilities Found ({auditReport.vulnerabilities.length})
                      </h3>
                      
                      {auditReport.vulnerabilities.length === 0 ? (
                        <div className="flex items-center gap-2 text-green-400 p-3 bg-green-500/10 
                                        rounded-lg border border-green-500/30">
                          <CheckCircle className="w-5 h-5" />
                          <span>No critical vulnerabilities detected!</span>
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {auditReport.vulnerabilities.map((vuln, idx) => (
                            <motion.div
                              key={idx}
                              initial={{ opacity: 0, x: -20 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: idx * 0.1 }}
                              className={`p-4 rounded-lg border ${
                                vuln.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/50' :
                                vuln.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/50' :
                                vuln.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' :
                                'bg-blue-500/10 border-blue-500/50'
                              }`}
                            >
                              <div className="flex items-start gap-3">
                                <div className={`px-2 py-1 rounded text-xs font-bold ${
                                  vuln.severity === 'CRITICAL' ? 'bg-red-500 text-white' :
                                  vuln.severity === 'HIGH' ? 'bg-orange-500 text-white' :
                                  vuln.severity === 'MEDIUM' ? 'bg-yellow-500 text-black' :
                                  'bg-blue-500 text-white'
                                }`}>
                                  {vuln.severity}
                                </div>
                                <div className="flex-1">
                                  <p className="font-semibold text-white mb-1">{vuln.type}</p>
                                  <p className="text-sm text-gray-400 mb-1">{vuln.description}</p>
                                  {vuln.location && (
                                    <p className="text-xs text-gray-500 font-mono">{vuln.location}</p>
                                  )}
                                </div>
                              </div>
                            </motion.div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Gas Optimizations */}
                    {auditReport.gasOptimizations.length > 0 && (
                      <div className="bg-slate-800/50 rounded-xl p-6 border border-slate-700/50">
                        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                          <Sparkles className="w-5 h-5 text-cyan-400" />
                          Gas Optimization Tips
                        </h3>
                        <ul className="space-y-2">
                          {auditReport.gasOptimizations.map((tip, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-gray-300">
                              <span className="text-cyan-400 mt-1">•</span>
                              <span className="text-sm">{tip}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}

        {/* ========================================
            MODULE B: EXIF GHOST CLEANER
            ======================================== */}
        {activeTab === 'exif' && (
          <motion.div
            key="exif"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <Image className="w-6 h-6 text-green-400" />
                  <h2 className="text-2xl font-bold text-white">EXIF Metadata Cleaner</h2>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={loadSampleExif}
                    className="text-sm text-green-400 hover:text-green-300 flex items-center gap-2 
                               px-3 py-1.5 rounded-lg border border-green-500/30 hover:bg-green-500/10 
                               transition-all font-semibold"
                  >
                    <Sparkles className="w-4 h-4" />
                    Load Sample
                  </button>
                  <div className="hidden sm:flex items-center gap-2 text-xs text-gray-500 
                                  px-3 py-1 bg-slate-800/50 rounded-full border border-slate-700/30">
                    <Info className="w-3 h-3" />
                    100% Client-Side
                  </div>
                </div>
              </div>

              {/* File Upload */}
              <div className="mb-6">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  onChange={handleImageUpload}
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="w-full py-12 border-2 border-dashed border-slate-600 rounded-xl 
                             hover:border-green-500/50 hover:bg-slate-800/30 transition-all 
                             flex flex-col items-center justify-center gap-3 group"
                >
                  <Image className="w-12 h-12 text-gray-500 group-hover:text-green-400 transition-colors" />
                  <p className="text-gray-400 group-hover:text-gray-300">
                    Click to upload an image
                  </p>
                  <p className="text-xs text-gray-600">
                    Supported: JPG, PNG (with EXIF metadata)
                  </p>
                </button>
              </div>

              {/* Image Preview & EXIF Data */}
              {selectedImage && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Preview */}
                  <div className="space-y-4">
                    <h3 className="font-semibold text-white flex items-center gap-2">
                      <Image className="w-4 h-4" />
                      Image Preview
                    </h3>
                    {imagePreview && (
                      <div className="rounded-lg overflow-hidden border border-slate-700/50">
                        <img 
                          src={imagePreview} 
                          alt="Preview" 
                          className="w-full h-auto"
                        />
                      </div>
                    )}
                    <button
                      onClick={sanitizeAndDownload}
                      className="w-full py-3 bg-gradient-to-r from-green-500 to-emerald-500 
                                 rounded-lg font-semibold text-white hover:from-green-600 
                                 hover:to-emerald-600 transition-all flex items-center 
                                 justify-center gap-2 shadow-lg"
                    >
                      <Download className="w-5 h-5" />
                      Sanitize & Download
                    </button>
                  </div>

                  {/* EXIF Data */}
                  <div className="space-y-4">
                    <h3 className="font-semibold text-white flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      Metadata Found
                    </h3>
                    
                    {exifLoading ? (
                      <div className="flex items-center justify-center py-12">
                        <Loader2 className="w-8 h-8 text-green-400 animate-spin" />
                      </div>
                    ) : exifData ? (
                      <div className="space-y-3">
                        {/* GPS Location Warning */}
                        {exifData.gpsLatitude && exifData.gpsLongitude && (
                          <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
                            <div className="flex items-center gap-2 text-red-400 mb-2">
                              <MapPin className="w-5 h-5" />
                              <span className="font-bold">GPS Location Detected!</span>
                            </div>
                            <p className="text-sm text-gray-400 mb-2">
                              This image contains your exact location:
                            </p>
                            <code className="text-xs bg-slate-900/50 px-2 py-1 rounded block">
                              {exifData.gpsLatitude.toFixed(6)}, {exifData.gpsLongitude.toFixed(6)}
                            </code>
                          </div>
                        )}

                        {/* Device Info */}
                        {(exifData.make || exifData.model) && (
                          <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/30">
                            <p className="text-sm text-gray-400 mb-1">Device</p>
                            <p className="text-white font-mono text-sm">
                              {exifData.make} {exifData.model}
                            </p>
                          </div>
                        )}

                        {/* Date Time */}
                        {exifData.dateTime && (
                          <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/30">
                            <p className="text-sm text-gray-400 mb-1">Captured</p>
                            <p className="text-white font-mono text-sm">{exifData.dateTime}</p>
                          </div>
                        )}

                        {/* Warning Message */}
                        <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                          <p className="text-sm text-yellow-400">
                            ⚠️ Sharing images with this metadata can reveal your location and device information.
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center py-12 text-center">
                        <div>
                          <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-3" />
                          <p className="text-green-400 font-semibold mb-1">Clean Image</p>
                          <p className="text-sm text-gray-500">No sensitive EXIF metadata found</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ========================================
            MODULE C: BREACH RADAR
            ======================================== */}
        {activeTab === 'breach' && (
          <motion.div
            key="breach"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <ShieldAlert className="w-6 h-6 text-red-400" />
                  <h2 className="text-2xl font-bold text-white">Breach Intelligence Radar</h2>
                </div>
                <button
                  onClick={loadSampleBreach}
                  className="text-sm text-red-400 hover:text-red-300 flex items-center gap-2 
                             px-3 py-1.5 rounded-lg border border-red-500/30 hover:bg-red-500/10 
                             transition-all font-semibold"
                >
                  <Sparkles className="w-4 h-4" />
                  Load Sample
                </button>
              </div>

              {/* Email Input */}
              <div className="flex gap-2 mb-6">
                <input
                  type="email"
                  value={breachEmail}
                  onChange={(e) => setBreachEmail(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && runBreachCheck()}
                  placeholder="email@example.com"
                  className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-lg
                             text-white placeholder-gray-500 focus:border-red-500/50 
                             focus:outline-none transition-colors"
                  disabled={breachLoading}
                />
                <button
                  onClick={runBreachCheck}
                  disabled={breachLoading || !breachEmail.trim()}
                  className="px-6 py-3 bg-gradient-to-r from-red-500 to-orange-500 
                             rounded-lg font-semibold text-white
                             hover:from-red-600 hover:to-orange-600 
                             disabled:opacity-50 disabled:cursor-not-allowed
                             transition-all duration-200 flex items-center gap-2"
                >
                  {breachLoading ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-5 h-5" />
                      Check Breaches
                    </>
                  )}
                </button>
              </div>

              {/* Breach Results */}
              <AnimatePresence>
                {breachError && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="bg-red-500/10 border border-red-500/50 rounded-lg p-4"
                  >
                    <div className="flex items-center gap-2 text-red-400">
                      <XCircle className="w-5 h-5" />
                      <span>{breachError}</span>
                    </div>
                  </motion.div>
                )}

                {breachData && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="space-y-6"
                  >
                    {/* Risk Level Banner */}
                    <div className={`p-6 rounded-xl border-2 ${
                      breachData.riskLevel === 'HIGH' ? 'bg-red-500/20 border-red-500' :
                      breachData.riskLevel === 'MEDIUM' ? 'bg-yellow-500/20 border-yellow-500' :
                      'bg-green-500/20 border-green-500'
                    }`}>
                      <div className="flex items-center gap-3 mb-2">
                        <ShieldAlert className={`w-8 h-8 ${
                          breachData.riskLevel === 'HIGH' ? 'text-red-400' :
                          breachData.riskLevel === 'MEDIUM' ? 'text-yellow-400' :
                          'text-green-400'
                        }`} />
                        <div>
                          <p className="text-white font-bold text-xl">
                            Risk Level: {breachData.riskLevel}
                          </p>
                          <p className="text-gray-400 text-sm">
                            Based on historical breach data
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Breach Timeline */}
                    {breachData.breaches.length > 0 && (
                      <div className="bg-slate-800/50 rounded-xl p-6 border border-slate-700/50">
                        <h3 className="text-xl font-bold text-white mb-4">
                          Known Breaches ({breachData.breaches.length})
                        </h3>
                        <div className="space-y-3">
                          {breachData.breaches.map((breach, idx) => (
                            <motion.div
                              key={idx}
                              initial={{ opacity: 0, x: -20 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: idx * 0.1 }}
                              className={`p-4 rounded-lg border ${
                                breach.severity === 'HIGH' ? 'bg-red-500/10 border-red-500/50' :
                                breach.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/50' :
                                'bg-blue-500/10 border-blue-500/50'
                              }`}
                            >
                              <div className="flex items-center justify-between">
                                <div>
                                  <p className="font-semibold text-white">{breach.name}</p>
                                  <p className="text-sm text-gray-400">{breach.year}</p>
                                </div>
                                <div className={`px-3 py-1 rounded-full text-xs font-bold ${
                                  breach.severity === 'HIGH' ? 'bg-red-500 text-white' :
                                  breach.severity === 'MEDIUM' ? 'bg-yellow-500 text-black' :
                                  'bg-blue-500 text-white'
                                }`}>
                                  {breach.severity}
                                </div>
                              </div>
                            </motion.div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    <div className="bg-slate-800/50 rounded-xl p-6 border border-slate-700/50">
                      <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                        <CheckCircle className="w-5 h-5 text-green-400" />
                        Security Recommendations
                      </h3>
                      <ul className="space-y-2">
                        {breachData.recommendations.map((rec, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-gray-300">
                            <span className="text-green-400 mt-1">✓</span>
                            <span className="text-sm">{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}

        {/* ========================================
            MODULE D: PAYLOAD DECODER (CYBERCHEF LITE)
            ======================================== */}
        {activeTab === 'decoder' && (
          <motion.div
            key="decoder"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <Binary className="w-6 h-6 text-cyan-400" />
                  <h2 className="text-2xl font-bold text-white">Payload Decoder</h2>
                </div>
                <button
                  onClick={loadSampleDecoder}
                  className="text-sm text-cyan-400 hover:text-cyan-300 flex items-center gap-2 
                             px-3 py-1.5 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/10 
                             transition-all font-semibold"
                >
                  <Sparkles className="w-4 h-4" />
                  Load Sample
                </button>
              </div>

              {/* Operation Buttons */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 mb-6">
                <button
                  onClick={() => applyOperation('toBase64')}
                  className="px-3 py-2 bg-slate-800/50 hover:bg-cyan-500/20 border border-slate-700/50 
                             hover:border-cyan-500/50 rounded-lg text-sm font-semibold text-gray-300 
                             hover:text-cyan-400 transition-all"
                >
                  → Base64
                </button>
                <button
                  onClick={() => applyOperation('fromBase64')}
                  className="px-3 py-2 bg-slate-800/50 hover:bg-cyan-500/20 border border-slate-700/50 
                             hover:border-cyan-500/50 rounded-lg text-sm font-semibold text-gray-300 
                             hover:text-cyan-400 transition-all"
                >
                  ← Base64
                </button>
                <button
                  onClick={() => applyOperation('toHex')}
                  className="px-3 py-2 bg-slate-800/50 hover:bg-green-500/20 border border-slate-700/50 
                             hover:border-green-500/50 rounded-lg text-sm font-semibold text-gray-300 
                             hover:text-green-400 transition-all"
                >
                  → Hex
                </button>
                <button
                  onClick={() => applyOperation('fromHex')}
                  className="px-3 py-2 bg-slate-800/50 hover:bg-green-500/20 border border-slate-700/50 
                             hover:border-green-500/50 rounded-lg text-sm font-semibold text-gray-300 
                             hover:text-green-400 transition-all"
                >
                  ← Hex
                </button>
                <button
                  onClick={() => applyOperation('urlEncode')}
                  className="px-3 py-2 bg-slate-800/50 hover:bg-purple-500/20 border border-slate-700/50 
                             hover:border-purple-500/50 rounded-lg text-sm font-semibold text-gray-300 
                             hover:text-purple-400 transition-all"
                >
                  URL Encode
                </button>
                <button
                  onClick={() => applyOperation('urlDecode')}
                  className="px-3 py-2 bg-slate-800/50 hover:bg-purple-500/20 border border-slate-700/50 
                             hover:border-purple-500/50 rounded-lg text-sm font-semibold text-gray-300 
                             hover:text-purple-400 transition-all"
                >
                  URL Decode
                </button>
                <button
                  onClick={() => applyOperation('rot13')}
                  className="px-3 py-2 bg-slate-800/50 hover:bg-orange-500/20 border border-slate-700/50 
                             hover:border-orange-500/50 rounded-lg text-sm font-semibold text-gray-300 
                             hover:text-orange-400 transition-all"
                >
                  ROT13
                </button>
              </div>

              {/* Input/Output Panes */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Input */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-semibold text-gray-400">Input</label>
                    <button
                      onClick={() => copyToClipboard(decoderInput)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" />
                      Copy
                    </button>
                  </div>
                  <textarea
                    value={decoderInput}
                    onChange={(e) => setDecoderInput(e.target.value)}
                    placeholder="Enter data to encode/decode..."
                    className="w-full h-64 bg-slate-950/80 text-white font-mono text-sm p-4 
                               rounded-lg border border-slate-700/50 focus:border-cyan-500/50 
                               focus:outline-none resize-none scrollbar-thin 
                               scrollbar-thumb-cyan-500/30 scrollbar-track-slate-800/30"
                  />
                </div>

                {/* Output */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-semibold text-gray-400">Output</label>
                    <div className="flex items-center gap-2">
                      {decoderOperation && (
                        <span className="text-xs text-gray-500 bg-slate-800/50 px-2 py-1 rounded">
                          {decoderOperation}
                        </span>
                      )}
                      <button
                        onClick={() => copyToClipboard(decoderOutput)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                      >
                        <Copy className="w-3 h-3" />
                        Copy
                      </button>
                    </div>
                  </div>
                  <textarea
                    value={decoderOutput}
                    readOnly
                    placeholder="Output will appear here..."
                    className="w-full h-64 bg-slate-950/80 text-green-400 font-mono text-sm p-4 
                               rounded-lg border border-slate-700/50 resize-none scrollbar-thin 
                               scrollbar-thumb-green-500/30 scrollbar-track-slate-800/30"
                  />
                </div>
              </div>

              {/* Swap Button */}
              <div className="flex justify-center mt-4">
                <button
                  onClick={swapInputOutput}
                  disabled={!decoderOutput}
                  className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-lg 
                             font-semibold text-white hover:from-cyan-600 hover:to-blue-600 
                             disabled:opacity-50 disabled:cursor-not-allowed transition-all 
                             flex items-center gap-2 shadow-lg"
                >
                  <ArrowRight className="w-5 h-5 transform rotate-90" />
                  Swap Input ↔ Output
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

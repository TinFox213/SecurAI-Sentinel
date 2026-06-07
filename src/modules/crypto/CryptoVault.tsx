import React, { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { Lock, Unlock, Upload, Download, Shield, AlertTriangle, CheckCircle2, Loader2, FileCheck, Code, Sparkles, Copy } from 'lucide-react';
import CryptoJS from 'crypto-js';
import { analyzeAndFixCode } from '../../services/cryptoVaultService';
import { AutoRemediationResult, ThreatLevel } from '../../types/types';
import AnalysisResult from '../analysis/AnalysisResult';
import { toast } from 'react-hot-toast';

type OperationMode = 'encrypt' | 'decrypt';

const CryptoVault: React.FC = () => {
  const [mode, setMode] = useState<OperationMode>('encrypt');
  const [file, setFile] = useState<File | null>(null);
  const [securityKey, setSecurityKey] = useState('');
  const [processing, setProcessing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [remediationResult, setRemediationResult] = useState<AutoRemediationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // IaC Patching state
  const [iacPatch, setIacPatch] = useState<string | null>(null);
  const [isGeneratingIaC, setIsGeneratingIaC] = useState(false);
  const [iacFormat, setIacFormat] = useState('terraform');

  const isCodeFile = (fileName: string, fileType: string): boolean => {
    const codeExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.rb', '.go', '.rs', '.c', '.cpp', '.json', '.xml', '.sql', '.sh', '.bat'];
    const extension = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    return codeExtensions.includes(extension) || fileType.startsWith('text/');
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;

    setFile(selectedFile);
    setError(null);
    setRemediationResult(null);

    // Auto-scan code files for vulnerabilities
    if (mode === 'encrypt' && isCodeFile(selectedFile.name, selectedFile.type)) {
      setScanning(true);
      try {
        const content = await selectedFile.text();
        const result = await analyzeAndFixCode(selectedFile.name, content);
        setRemediationResult(result);
      } catch (err) {
        console.error('Auto-scan failed:', err);
        setError('Failed to analyze file for vulnerabilities');
        toast.error('Code analysis failed. Please try again.');
      } finally {
        setScanning(false);
      }
    }
  };

  const encryptFile = async (file: File, key: string): Promise<Blob> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const base64Data = e.target?.result as string;
          const encrypted = CryptoJS.AES.encrypt(base64Data, key).toString();
          const blob = new Blob([encrypted], { type: 'application/octet-stream' });
          resolve(blob);
        } catch (error) {
          reject(error);
        }
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  };

  const decryptFile = async (file: File, key: string): Promise<Blob> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const encryptedData = e.target?.result as string;
          const decrypted = CryptoJS.AES.decrypt(encryptedData, key);
          const base64Data = decrypted.toString(CryptoJS.enc.Utf8);
          
          if (!base64Data) {
            throw new Error('Decryption failed. Invalid key or corrupted file.');
          }

          // Convert base64 back to blob
          const byteCharacters = atob(base64Data.split(',')[1]);
          const byteNumbers = new Array(byteCharacters.length);
          for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
          }
          const byteArray = new Uint8Array(byteNumbers);
          const blob = new Blob([byteArray]);
          resolve(blob);
        } catch (error) {
          reject(error);
        }
      };
      reader.onerror = reject;
      reader.readAsText(file);
    });
  };

  const downloadFile = (blob: Blob, fileName: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleProcess = async () => {
    if (!file || !securityKey) {
      setError('Please select a file and enter a security key');
      toast.error('Select a file and enter a security key first.');
      return;
    }

    setProcessing(true);
    setError(null);

    try {
      if (mode === 'encrypt') {
        const encryptedBlob = await encryptFile(file, securityKey);
        downloadFile(encryptedBlob, `${file.name}.encrypted`);
      } else {
        const decryptedBlob = await decryptFile(file, securityKey);
        const originalName = file.name.replace('.encrypted', '');
        downloadFile(decryptedBlob, originalName);
      }
    } catch (err) {
      setError(mode === 'encrypt' ? 'Encryption failed' : 'Decryption failed. Check your key.');
      toast.error(mode === 'encrypt' ? 'Encryption failed.' : 'Decryption failed. Check your key.');
    } finally {
      setProcessing(false);
    }
  };

  const downloadOriginal = () => {
    if (!file) return;
    downloadFile(file, file.name);
  };

  const downloadPatched = async () => {
    if (!remediationResult?.fixed_content) return;
    const blob = new Blob([remediationResult.fixed_content], { type: 'text/plain' });
    const patchedName = file!.name.replace(/(\.[^.]+)$/, '.patched$1');
    downloadFile(blob, patchedName);
  };

  return (
    <div className="space-y-6">
      {/* Mode Toggle */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-2xl"
      >
        <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
          <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Operation Mode
          </h3>
          <button
            onClick={async () => {
              setMode('encrypt');
              const content = `// Vulnerable JavaScript file\nconst dbPassword = "SuperSecretAdminPassword123";\nconst targetHost = "http://api.internal/v1";\n\nfunction processUserData(userInput) {\n  // Dangerous eval execution\n  return eval(userInput);\n}\n`;
              const mockFile = new File([content], 'vulnerable.js', { type: 'text/javascript' });
              setFile(mockFile);
              setSecurityKey('DemoSecurityKey99!');
              setScanning(true);
              setRemediationResult(null);
              setError(null);
              try {
                const result = await analyzeAndFixCode('vulnerable.js', content);
                setRemediationResult(result);
                toast.success('Sample vulnerable file loaded and analyzed.');
              } catch (err) {
                console.error('Auto-scan failed:', err);
                setError('Failed to analyze file for vulnerabilities');
                toast.error('Code analysis failed.');
              } finally {
                setScanning(false);
              }
            }}
            className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 text-xs font-semibold transition-all"
          >
            Load Sample Data
          </button>
        </div>
        
        <div className="flex gap-4">
          <button
            onClick={() => setMode('encrypt')}
            className={`flex-1 flex items-center justify-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all ${
              mode === 'encrypt'
                ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-500/50'
                : 'bg-slate-800/60 text-slate-400 hover:bg-slate-700/60'
            }`}
          >
            <Lock className="w-4 h-4" />
            Encrypt & Sanitize
          </button>
          <button
            onClick={() => setMode('decrypt')}
            className={`flex-1 flex items-center justify-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all ${
              mode === 'decrypt'
                ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-500/50'
                : 'bg-slate-800/60 text-slate-400 hover:bg-slate-700/60'
            }`}
          >
            <Unlock className="w-4 h-4" />
            Decrypt
          </button>
        </div>
      </motion.div>

      {/* File Upload */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-2xl"
      >
        <h3 className="text-lg font-bold text-slate-100 mb-4 flex items-center gap-2">
          <Upload className="w-5 h-5 text-purple-400" />
          File Selection
        </h3>

        <div
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-slate-700 hover:border-cyan-500/50 rounded-lg p-8 text-center cursor-pointer transition-all bg-slate-950/50"
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileSelect}
            className="hidden"
            accept="*/*"
          />
          {file ? (
            <div className="space-y-2">
              <FileCheck className="w-12 h-12 text-emerald-500 mx-auto" />
              <p className="text-slate-300 font-medium">{file.name}</p>
              <p className="text-xs text-slate-500">{(file.size / 1024).toFixed(2)} KB</p>
              {scanning && (
                <div className="flex items-center justify-center gap-2 text-cyan-400 mt-4">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Scanning for vulnerabilities...</span>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              <Upload className="w-12 h-12 text-slate-600 mx-auto" />
              <p className="text-slate-400">Click to select any file</p>
              <p className="text-xs text-slate-600">All file types supported</p>
            </div>
          )}
        </div>

        {/* Security Key Input */}
        <div className="mt-6">
          <label className="block text-sm font-semibold text-slate-400 mb-2">
            Security Key (Password)
          </label>
          <input
            type="password"
            value={securityKey}
            onChange={(e) => setSecurityKey(e.target.value)}
            placeholder="Enter encryption/decryption key"
            className="w-full bg-slate-950/50 text-slate-200 px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500/50 border border-white/5"
          />
          <p className="text-xs text-slate-600 mt-2">
            ⚠️ Keep this key safe. You'll need it to decrypt the file.
          </p>
        </div>

        {/* Process Button */}
        <button
          onClick={handleProcess}
          disabled={!file || !securityKey || processing}
          className="w-full mt-6 flex items-center justify-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800/60 disabled:text-slate-500 text-white font-semibold rounded-lg shadow-lg shadow-cyan-500/30 transition-all"
        >
          {processing ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Processing...
            </>
          ) : (
            <>
              <Download className="w-4 h-4" />
              {mode === 'encrypt' ? 'Encrypt & Download' : 'Decrypt & Download'}
            </>
          )}
        </button>
      </motion.div>

      {/* Error Display */}
      {error && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-red-500/10 backdrop-blur-sm border border-red-500/50 text-red-400 p-4 rounded-lg flex items-center gap-3 shadow-lg"
        >
          <AlertTriangle className="w-5 h-5" />
          {error}
        </motion.div>
      )}

      {/* Vulnerability Detection Results */}
      {remediationResult && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-6"
        >
          {/* Status Banner */}
          {remediationResult.is_vulnerable ? (
            <div className="bg-yellow-500/10 backdrop-blur-sm border border-yellow-500/50 rounded-lg p-6 shadow-lg">
              <div className="flex items-start gap-4">
                <AlertTriangle className="w-8 h-8 text-yellow-500 flex-shrink-0" />
                <div className="flex-1">
                  <h3 className="text-lg font-bold text-yellow-400 mb-2">
                    Vulnerabilities Detected & Auto-Fixed!
                  </h3>
                  <p className="text-slate-300 text-sm mb-4">
                    Security issues were found in your code. A patched version has been generated.
                  </p>
                  <div className="flex gap-3">
                    <button
                      onClick={downloadOriginal}
                      className="px-4 py-2 bg-slate-700/60 hover:bg-slate-600/60 text-slate-300 rounded-lg text-sm font-semibold transition-all"
                    >
                      Download Original
                    </button>
                    <button
                      onClick={downloadPatched}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition-all shadow-lg shadow-emerald-500/30"
                    >
                      <CheckCircle2 className="w-4 h-4 inline mr-2" />
                      Download Patched File
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-emerald-500/10 backdrop-blur-sm border border-emerald-500/50 rounded-lg p-6 shadow-lg">
              <div className="flex items-center gap-4">
                <CheckCircle2 className="w-8 h-8 text-emerald-500" />
                <div>
                  <h3 className="text-lg font-bold text-emerald-400 mb-1">
                    No Vulnerabilities Detected
                  </h3>
                  <p className="text-slate-300 text-sm">
                    Your file appears to be secure. You can proceed with encryption.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Security Analysis */}
          <AnalysisResult analysis={remediationResult.analysis} />
          
          {/* IaC Generator (High/Critical Only) */}
          {(remediationResult.analysis.threat_level === ThreatLevel.CRITICAL || remediationResult.analysis.threat_level === ThreatLevel.HIGH) && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              className="mt-6 bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-2xl"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                <div>
                  <h4 className="font-semibold text-emerald-400 flex items-center gap-2 text-lg">
                    <Code className="w-5 h-5" /> Autonomous IaC Patching
                  </h4>
                  <p className="text-sm text-slate-400 mt-1">Generate Infrastructure as Code (Terraform/Ansible/K8s) to mitigate this severe vulnerability at the infrastructure layer.</p>
                </div>
                <div className="flex items-center gap-2">
                  <select 
                    value={iacFormat} 
                    onChange={e => setIacFormat(e.target.value)}
                    className="bg-slate-950 border border-slate-700 text-sm text-slate-300 rounded px-3 py-2 focus:outline-none focus:ring-1 focus:ring-emerald-500/50"
                  >
                    <option value="terraform">Terraform</option>
                    <option value="kubernetes">Kubernetes</option>
                    <option value="ansible">Ansible</option>
                  </select>
                  <button 
                    onClick={async () => {
                      setIsGeneratingIaC(true);
                      try {
                        const res = await fetch('http://localhost:3001/remediate/iac', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ 
                            cveId: 'Code-Level Vulnerability', 
                            description: remediationResult.analysis.summary, 
                            format: iacFormat 
                          })
                        });
                        const data = await res.json();
                        if (data.success) {
                          setIacPatch(data.patch);
                        }
                      } catch (e) {
                        setIacPatch('// Failed to generate patch.');
                      } finally {
                        setIsGeneratingIaC(false);
                      }
                    }}
                    disabled={isGeneratingIaC}
                    className="px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-400 rounded text-sm font-semibold transition-all flex items-center gap-2 disabled:opacity-50"
                  >
                    {isGeneratingIaC ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                    Generate IaC
                  </button>
                </div>
              </div>
              
              {iacPatch && (
                <div className="relative mt-4">
                  <pre className="bg-slate-950 p-4 rounded-lg font-mono text-sm text-emerald-300 border border-slate-800 overflow-x-auto shadow-inner">
                    {iacPatch}
                  </pre>
                  <button 
                    onClick={() => { navigator.clipboard.writeText(iacPatch); alert('IaC Patch Copied!'); }}
                    className="absolute top-3 right-3 p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition-all"
                    title="Copy to Clipboard"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              )}
            </motion.div>
          )}
        </motion.div>
      )}
    </div>
  );
};

export default CryptoVault;

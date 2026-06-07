import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Gamepad2, Target, Database, Lock, FileText, 
  CheckCircle, XCircle, Trophy, Star, Zap, BookOpen, Loader2
} from 'lucide-react';
import { 
  generateDojoChallenge,
  type PhishingChallenge,
  type SQLiChallenge,
  type CryptoChallenge,
  type LogHunterChallenge,
  type PentestChallenge
} from '../../services/geminiService';
import TeachingMode from './TeachingMode';
import { toast } from 'react-hot-toast';

type GameTab = 'phishing' | 'sqli' | 'crypto' | 'loghunter' | 'pentest';

interface GameScore {
  phishing: number;
  sqli: number;
  crypto: number;
  loghunter: number;
  pentest: number;
}

export default function CyberDojo() {
  const [activeTab, setActiveTab] = useState<GameTab>('phishing');
  const [showTeaching, setShowTeaching] = useState(false);
  const [scores, setScores] = useState<GameScore>({
    phishing: 0,
    sqli: 0,
    crypto: 0,
    loghunter: 0,
    pentest: 0
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl">
              <Gamepad2 className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Cyber Dojo</h1>
              <p className="text-slate-400">Master Security Skills Through Gamification</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowTeaching(true)}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-xl font-semibold hover:shadow-lg hover:shadow-cyan-500/50 transition-all"
            >
              <BookOpen className="w-5 h-5" />
              Learn to Play
            </button>
            <div className="text-right">
              <div className="text-sm text-slate-400">Total Score</div>
              <div className="text-2xl font-bold text-yellow-400 flex items-center gap-2">
                <Trophy className="w-5 h-5" />
                {Object.values(scores).reduce((a, b) => (a as number) + (b as number), 0)}
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Tab Navigation */}
      <div className="flex gap-3 overflow-x-auto pb-2">
        {[
          { id: 'phishing', label: 'Phishing Detective', icon: Target },
          { id: 'sqli', label: 'SQLi Playground', icon: Database },
          { id: 'crypto', label: 'Crypto Cracker', icon: Lock },
          { id: 'loghunter', label: 'Log Hunter', icon: FileText },
          { id: 'pentest', label: 'Auto-Pentest Staging', icon: Zap }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as GameTab)}
            className={`flex items-center gap-2 px-6 py-3 rounded-xl font-semibold transition-all ${
              activeTab === tab.id
                ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg shadow-cyan-500/50'
                : 'bg-slate-800/60 text-slate-400 hover:bg-slate-700/60'
            }`}
          >
            <tab.icon className="w-5 h-5" />
            {tab.label}
            {scores[tab.id as keyof GameScore] > 0 && (
              <span className="ml-1 px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded-full text-xs">
                {scores[tab.id as keyof GameScore]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Game Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.3 }}
      >
        {activeTab === 'phishing' && <PhishingDetective onScore={(points) => setScores(s => ({ ...s, phishing: s.phishing + points }))} />}
        {activeTab === 'sqli' && <SQLiPlayground onScore={(points) => setScores(s => ({ ...s, sqli: s.sqli + points }))} />}
        {activeTab === 'crypto' && <CryptoCracker onScore={(points) => setScores(s => ({ ...s, crypto: s.crypto + points }))} />}
        {activeTab === 'loghunter' && <LogHunter onScore={(points) => setScores(s => ({ ...s, loghunter: s.loghunter + points }))} />}
        {activeTab === 'pentest' && <PentestSimulation onScore={(points) => setScores(s => ({ ...s, pentest: s.pentest + points }))} />}
      </motion.div>

      {/* Teaching Mode Overlay */}
      <AnimatePresence>
        {showTeaching && (
          <TeachingMode 
            gameType={activeTab} 
            onClose={() => setShowTeaching(false)} 
          />
        )}
      </AnimatePresence>
    </div>
  );
}

// ==================== Game 1: Phishing Detective ====================
function PhishingDetective({ onScore }: { onScore: (points: number) => void }) {
  const [challenge, setChallenge] = useState<PhishingChallenge | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedElements, setSelectedElements] = useState<string[]>([]);
  const [showResult, setShowResult] = useState(false);
  const [score, setScore] = useState(0);
  const [previousThemes, setPreviousThemes] = useState<string[]>([]);

  const loadNewChallenge = async () => {
    setLoading(true);
    setSelectedElements([]);
    setShowResult(false);
    setScore(0);
    try {
      const newChallenge = await generateDojoChallenge('phishing', previousThemes) as PhishingChallenge;
      setChallenge(newChallenge);
      if (newChallenge.theme && !previousThemes.includes(newChallenge.theme)) {
        setPreviousThemes([...previousThemes, newChallenge.theme]);
      }
    } catch (error) {
      console.error('Error generating phishing challenge:', error);
      toast.error('Challenge generation unavailable. Loaded fallback scenario.');
      // Fallback challenge if API fails
      setChallenge({
        sender: 'noreply@paypa1-secure.com',
        subject: 'ACTION REQUIRED: Verify Your Account',
        body: 'We detected unusual activity on your account. Click here to verify your identity within 24 hours or your account will be locked permanently.',
        indicators: [
          { text: 'paypa1-secure.com', reason: 'Fake domain using "1" instead of "l"', type: 'domain' },
          { text: 'within 24 hours', reason: 'Creates false urgency', type: 'urgency' },
          { text: 'locked permanently', reason: 'Threatening language', type: 'urgency' }
        ],
        theme: 'Banking'
      });
    }
    setLoading(false);
  };

  useEffect(() => {
    loadNewChallenge();
  }, []);

  const handleTextSelection = () => {
    const selection = window.getSelection();
    const text = selection?.toString().trim();
    if (text && text.length > 3 && !selectedElements.includes(text)) {
      setSelectedElements([...selectedElements, text]);
    }
  };

  const checkAnswers = () => {
    if (!challenge) return;
    
    let correctCount = 0;
    const suspiciousTexts = challenge.indicators.map(el => el.text.toLowerCase());
    
    selectedElements.forEach(selected => {
      if (suspiciousTexts.some(sus => selected.toLowerCase().includes(sus) || sus.includes(selected.toLowerCase()))) {
        correctCount++;
      }
    });

    const totalIndicators = challenge.indicators.length;
    const points = correctCount === totalIndicators ? 10 : Math.max(0, correctCount * 5 - (totalIndicators - correctCount) * 2);
    setScore(points);
    onScore(points);
    setShowResult(true);
  };

  return (
    <div className="space-y-4">
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Target className="w-6 h-6 text-red-400" />
            Phishing Detective
            {challenge?.theme && (
              <span className="text-sm font-normal text-slate-400">- {challenge.theme}</span>
            )}
          </h2>
          <div className="flex gap-2">
            <button
              onClick={() => {
                setChallenge({
                  sender: 'noreply@paypa1-secure.com',
                  subject: 'ACTION REQUIRED: Verify Your Account',
                  body: 'We detected unusual activity on your account. Click here to verify your identity within 24 hours or your account will be locked permanently.',
                  indicators: [
                    { text: 'paypa1-secure.com', reason: 'Fake domain using "1" instead of "l"', type: 'domain' },
                    { text: 'within 24 hours', reason: 'Creates false urgency', type: 'urgency' },
                    { text: 'locked permanently', reason: 'Threatening language', type: 'urgency' }
                  ],
                  theme: 'Banking'
                });
                setSelectedElements(['paypa1-secure.com', 'within 24 hours', 'locked permanently']);
                toast.success('Sample phishing scenario loaded and solved.');
              }}
              className="px-4 py-2 bg-purple-500/20 border border-purple-500/40 text-purple-300 hover:bg-purple-500/30 rounded-lg text-sm font-semibold transition-all"
            >
              Load Sample Data
            </button>
            <button
              onClick={loadNewChallenge}
              disabled={loading}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Generating...
                </>
              ) : (
                'New Challenge'
              )}
            </button>
          </div>
        </div>

        <p className="text-slate-400 mb-6">
          Select suspicious text in the email below. Look for fake domains, urgency triggers, grammar errors, or unusual requests.
        </p>

        {loading ? (
          <div className="bg-slate-800/60 rounded-lg p-12 flex flex-col items-center justify-center">
            <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mb-4" />
            <p className="text-slate-400 text-center">
              🤖 AI is crafting a unique phishing scenario...
              <br />
              <span className="text-sm text-slate-500">Hacking the mainframe...</span>
            </p>
          </div>
        ) : challenge ? (
          <>
            <div 
              className="bg-slate-800/60 rounded-lg p-6 mb-4 cursor-text select-text"
              onMouseUp={handleTextSelection}
            >
              <div className="mb-4 pb-4 border-b border-slate-700">
                <div className="text-sm text-slate-500">From:</div>
                <div className="text-white font-mono">{challenge.sender}</div>
                <div className="text-sm text-slate-500 mt-2">Subject:</div>
                <div className="text-white font-semibold">{challenge.subject}</div>
              </div>
              <div className="text-slate-300 whitespace-pre-wrap leading-relaxed">
                {challenge.body}
              </div>
            </div>

            {selectedElements.length > 0 && (
              <div className="mb-4">
                <div className="text-sm text-slate-400 mb-2">Selected Suspicious Elements:</div>
                <div className="flex flex-wrap gap-2">
                  {selectedElements.map((el, idx) => (
                    <span key={idx} className="px-3 py-1 bg-red-500/20 text-red-400 rounded-lg text-sm border border-red-500/30">
                      {el}
                      <button 
                        onClick={() => setSelectedElements(selectedElements.filter((_, i) => i !== idx))}
                        className="ml-2 text-red-300 hover:text-red-100"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}

            <button
              onClick={checkAnswers}
              disabled={selectedElements.length === 0 || showResult}
              className="w-full py-3 bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Submit Answer
            </button>

            {showResult && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="mt-4 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg"
              >
                <div className="flex items-center gap-2 mb-2">
                  <Star className="w-5 h-5 text-yellow-400" />
                  <span className="text-yellow-400 font-semibold">Score: +{score} points</span>
                </div>
                <div className="text-sm text-slate-300 mb-2">Actual Suspicious Elements:</div>
                <ul className="space-y-2">
                  {challenge.indicators.map((el, idx) => (
                    <li key={idx} className="text-sm bg-slate-800/60 p-2 rounded">
                      <span className="text-red-400 font-mono">"{el.text}"</span>
                      <span className="text-slate-400 ml-2">- {el.reason}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            )}
          </>
        ) : null}
      </div>
    </div>
  );
}

// ==================== Game 2: SQLi Playground ====================
function SQLiPlayground({ onScore }: { onScore: (points: number) => void }) {
  const [challenge, setChallenge] = useState<SQLiChallenge | null>(null);
  const [loading, setLoading] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [result, setResult] = useState<'idle' | 'success' | 'fail'>('idle');
  const [dbDump, setDbDump] = useState<string[]>([]);

  const loadNewChallenge = async () => {
    setLoading(true);
    setResult('idle');
    setUsername('');
    setPassword('');
    setDbDump([]);
    try {
      const newChallenge = await generateDojoChallenge('sqli') as SQLiChallenge;
      setChallenge(newChallenge);
    } catch (error) {
      console.error('Error generating SQLi challenge:', error);
      toast.error('Challenge generation unavailable. Loaded fallback scenario.');
      setChallenge({
        context: 'Corporate Intranet Login',
        hint: 'The database uses a "users" table with username and password columns',
        vulnerability_type: 'Authentication Bypass',
        target_table: 'users',
        difficulty: 'easy'
      });
    }
    setLoading(false);
  };

  useEffect(() => {
    loadNewChallenge();
  }, []);

  const handleSubmit = () => {
    const sqliPattern = /('\s*OR\s*'?1'?\s*=\s*'?1|--|\bOR\b.*=.*|UNION|;.*DROP)/i;
    
    if (sqliPattern.test(username) || sqliPattern.test(password)) {
      setResult('success');
      const points = challenge?.difficulty === 'hard' ? 70 : challenge?.difficulty === 'medium' ? 60 : 50;
      onScore(points);
      setDbDump([
        `admin | admin@${challenge?.target_table || 'corp'}.com | $2a$10$N9qo8uLOickgx2ZMRZoMye`,
        `john.doe | john@${challenge?.target_table || 'corp'}.com | $2a$10$kH9qYLOickgx2ZMRZoMpf`,
        `jane.smith | jane@${challenge?.target_table || 'corp'}.com | $2a$10$pL3rZLOickgx2ZMRZoQwe`
      ]);
    } else {
      setResult('fail');
    }
  };

  const reset = () => {
    loadNewChallenge();
  };

  return (
    <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-orange-400" />
          SQLi Playground
          {challenge && (
            <span className="text-sm font-normal text-slate-400">- {challenge.context}</span>
          )}
        </h2>
        <div className="flex gap-2">
          <button
            onClick={() => {
              setChallenge({
                context: 'Corporate Intranet Login',
                hint: 'The database uses a "users" table with username and password columns',
                vulnerability_type: 'Authentication Bypass',
                target_table: 'users',
                difficulty: 'easy'
              });
              setUsername("' OR 1=1 --");
              setPassword("anything");
              toast.success('Sample SQLi login payload loaded.');
            }}
            className="px-4 py-2 bg-purple-500/20 border border-purple-500/40 text-purple-300 hover:bg-purple-500/30 rounded-lg text-sm font-semibold transition-all"
          >
            Load Sample Data
          </button>
          <button 
            onClick={reset} 
            disabled={loading}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Generating...
              </>
            ) : (
              'New Challenge'
            )}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="bg-slate-800/60 rounded-lg p-12 flex flex-col items-center justify-center">
          <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mb-4" />
          <p className="text-slate-400 text-center">
            🤖 AI is crafting a SQLi scenario...
            <br />
            <span className="text-sm text-slate-500">Preparing vulnerable database...</span>
          </p>
        </div>
      ) : challenge ? (
        <>
          <p className="text-slate-400 mb-6">
            Exploit this vulnerable {challenge.context.toLowerCase()} using SQL injection. {challenge.vulnerability_type}!
            <br />
            <span className="text-yellow-400 text-sm">Hint: {challenge.hint}</span>
            <br />
            <span className="text-purple-400 text-xs">Difficulty: {challenge.difficulty.toUpperCase()}</span>
          </p>

          <div className="bg-slate-800/60 rounded-lg p-6 mb-4">
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-2">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={result !== 'idle'}
                  placeholder="admin"
                  className="w-full px-4 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-500 font-mono disabled:opacity-50"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-2">Password</label>
                <input
                  type="text"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={result !== 'idle'}
                  placeholder="password"
                  className="w-full px-4 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-500 font-mono disabled:opacity-50"
                />
              </div>
              <button
                onClick={handleSubmit}
                disabled={result !== 'idle'}
                className="w-full py-3 bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white font-semibold rounded-lg transition-all disabled:opacity-50"
              >
                Login
              </button>
            </div>
          </div>
        </>
      ) : null}

      {result === 'success' && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg mb-4"
        >
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle className="w-5 h-5 text-green-400" />
            <span className="text-green-400 font-semibold">SQL Injection Successful! +{challenge?.difficulty === 'hard' ? 70 : challenge?.difficulty === 'medium' ? 60 : 50} points</span>
          </div>
          <div className="text-sm text-slate-300 mb-2">Database Dump ({challenge?.target_table || 'users'} table):</div>
          <div className="bg-slate-900/80 p-3 rounded font-mono text-xs text-green-400 space-y-1">
            {dbDump.map((row, idx) => (
              <div key={idx}>{row}</div>
            ))}
          </div>
        </motion.div>
      )}

      {result === 'fail' && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg"
        >
          <div className="flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-400" />
            <span className="text-red-400 font-semibold">Invalid credentials. Try SQL injection!</span>
          </div>
        </motion.div>
      )}
    </div>
  );
}

// ==================== Game 3: Crypto Cracker ====================
function CryptoCracker({ onScore }: { onScore: (points: number) => void }) {
  const [challenge, setChallenge] = useState<CryptoChallenge | null>(null);
  const [loading, setLoading] = useState(false);
  const [input, setInput] = useState('');
  const [result, setResult] = useState<'idle' | 'success' | 'fail'>('idle');

  const loadNewChallenge = async () => {
    setLoading(true);
    setResult('idle');
    setInput('');
    try {
      const newChallenge = await generateDojoChallenge('crypto') as CryptoChallenge;
      setChallenge(newChallenge);
    } catch (error) {
      console.error('Error generating crypto challenge:', error);
      toast.error('Challenge generation unavailable. Loaded fallback scenario.');
      setChallenge({
        encrypted_string: 'RkxBR3tDWUJFUl9NQVNURVJfMjAyNn0=',
        clear_text: 'FLAG{CYBER_MASTER_2026}',
        encoding_type: 'base64',
        difficulty_hint: 'Look for the padding characters'
      });
    }
    setLoading(false);
  };

  useEffect(() => {
    loadNewChallenge();
  }, []);

  const decode = (text: string, type: string): string => {
    try {
      if (type === 'base64') {
        return atob(text);
      } else if (type === 'hex') {
        return text.match(/.{1,2}/g)?.map(hex => String.fromCharCode(parseInt(hex, 16))).join('') || '';
      } else if (type === 'rot13') {
        return text.replace(/[a-zA-Z]/g, (char) => {
          const code = char.charCodeAt(0);
          const base = code <= 90 ? 65 : 97; // A or a
          return String.fromCharCode(((code - base + 13) % 26) + base);
        });
      }
      return '';
    } catch {
      return '';
    }
  };

  const handleDecode = () => {
    if (!challenge) return;
    const decoded = decode(challenge.encrypted_string, challenge.encoding_type);
    setInput(decoded);
  };

  const handleSubmit = () => {
    if (!challenge) return;
    if (input.trim().toUpperCase() === challenge.clear_text.toUpperCase()) {
      setResult('success');
      onScore(30);
    } else {
      setResult('fail');
    }
  };

  const reset = () => {
    loadNewChallenge();
  };

  return (
    <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-purple-400" />
          Crypto Cracker
        </h2>
        <div className="flex gap-2">
          <button
            onClick={() => {
              setChallenge({
                encrypted_string: 'RkxBR3tDWUJFUl9NQVNURVJfMjAyNn0=',
                clear_text: 'FLAG{CYBER_MASTER_2026}',
                encoding_type: 'base64',
                difficulty_hint: 'Look for the padding characters'
              });
              setInput('FLAG{CYBER_MASTER_2026}');
              toast.success('Sample encrypted string and decoded flag loaded.');
            }}
            className="px-4 py-2 bg-purple-500/20 border border-purple-500/40 text-purple-300 hover:bg-purple-500/30 rounded-lg text-sm font-semibold transition-all"
          >
            Load Sample Data
          </button>
          <button 
            onClick={reset} 
            disabled={loading}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Generating...
              </>
            ) : (
              'New Challenge'
            )}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="bg-slate-800/60 rounded-lg p-12 flex flex-col items-center justify-center">
          <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mb-4" />
          <p className="text-slate-400 text-center">
            🤖 AI is encoding a secret...
            <br />
            <span className="text-sm text-slate-500">Encrypting challenge...</span>
          </p>
        </div>
      ) : challenge ? (
        <>
          <p className="text-slate-400 mb-6">
            Decode the encrypted string to find the hidden flag. Use the decoder tool below!
            <br />
            <span className="text-yellow-400 text-sm">Encoding: {challenge.encoding_type.toUpperCase()}</span>
            <br />
            <span className="text-purple-400 text-xs">Hint: {challenge.difficulty_hint}</span>
          </p>

          <div className="bg-slate-800/60 rounded-lg p-6 mb-4">
            <div className="text-sm text-slate-400 mb-2">Encrypted String:</div>
            <div className="bg-slate-900/80 p-4 rounded font-mono text-cyan-400 break-all mb-4">
              {challenge.encrypted_string}
            </div>

            <button
              onClick={handleDecode}
              disabled={result !== 'idle'}
              className="w-full py-2 bg-purple-500 hover:bg-purple-600 text-white font-semibold rounded-lg transition-colors mb-4 disabled:opacity-50"
            >
              🔓 Decode {challenge.encoding_type.toUpperCase()}
            </button>

            <div className="text-sm text-slate-400 mb-2">Your Answer:</div>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={result !== 'idle'}
              placeholder="Enter the decoded flag..."
              className="w-full px-4 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-500 font-mono mb-4 disabled:opacity-50"
            />

            <button
              onClick={handleSubmit}
              disabled={result !== 'idle'}
              className="w-full py-3 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white font-semibold rounded-lg transition-all disabled:opacity-50"
            >
              Submit Flag
            </button>
          </div>
        </>
      ) : null}

      {result === 'success' && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg"
        >
          <div className="flex items-center gap-2">
            <CheckCircle className="w-5 h-5 text-green-400" />
            <span className="text-green-400 font-semibold">Correct! +30 points 🎉</span>
          </div>
        </motion.div>
      )}

      {result === 'fail' && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg"
        >
          <div className="flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-400" />
            <span className="text-red-400 font-semibold">Incorrect. Try again!</span>
          </div>
        </motion.div>
      )}
    </div>
  );
}

// ==================== Game 4: Log Hunter ====================
function LogHunter({ onScore }: { onScore: (points: number) => void }) {
  const [challenge, setChallenge] = useState<LogHunterChallenge | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedLine, setSelectedLine] = useState<number | null>(null);
  const [result, setResult] = useState<'idle' | 'success' | 'fail'>('idle');

  const loadNewChallenge = async () => {
    setLoading(true);
    setResult('idle');
    setSelectedLine(null);
    try {
      const newChallenge = await generateDojoChallenge('log') as LogHunterChallenge;
      setChallenge(newChallenge);
    } catch (error) {
      console.error('Error generating log challenge:', error);
      toast.error('Challenge generation unavailable. Loaded fallback scenario.');
      setChallenge({
        log_block: `192.168.1.45 - - [12/Jan/2026:10:23:15 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
10.0.0.12 - - [12/Jan/2026:10:23:18 +0000] "GET /assets/style.css HTTP/1.1" 200 12456 "-" "Mozilla/5.0"
192.168.1.78 - - [12/Jan/2026:10:23:22 +0000] "POST /api/login HTTP/1.1" 200 245 "-" "Chrome/120.0"
203.0.113.45 - - [12/Jan/2026:10:23:28 +0000] "GET /admin.php?id=1' OR 1=1-- HTTP/1.1" 404 0 "-" "sqlmap/1.7.2"
172.16.0.5 - - [12/Jan/2026:10:23:25 +0000] "GET /dashboard HTTP/1.1" 200 8934 "-" "Firefox/121.0"
192.168.1.45 - - [12/Jan/2026:10:23:30 +0000] "GET /about.html HTTP/1.1" 200 3421 "-" "Safari/17.0"`,
        malicious_line_index: 3,
        attack_type: 'SQL Injection',
        explanation: 'Contains SQL injection payload and suspicious sqlmap user agent'
      });
    }
    setLoading(false);
  };

  useEffect(() => {
    loadNewChallenge();
  }, []);

  const handleLineClick = (index: number) => {
    if (result !== 'idle') return;
    setSelectedLine(index);
  };

  const handleSubmit = () => {
    if (!challenge) return;
    if (selectedLine === challenge.malicious_line_index) {
      setResult('success');
      onScore(40);
    } else {
      setResult('fail');
    }
  };

  const reset = () => {
    loadNewChallenge();
  };

  const logLines = challenge?.log_block.split('\n').filter(line => line.trim()) || [];

  return (
    <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <FileText className="w-6 h-6 text-yellow-400" />
          Log Hunter
          {challenge && result === 'success' && (
            <span className="text-sm font-normal text-slate-400">- {challenge.attack_type}</span>
          )}
        </h2>
        <div className="flex gap-2">
          <button
            onClick={() => {
              setChallenge({
                log_block: `192.168.1.45 - - [12/Jan/2026:10:23:15 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"\n10.0.0.12 - - [12/Jan/2026:10:23:18 +0000] "GET /assets/style.css HTTP/1.1" 200 12456 "-" "Mozilla/5.0"\n192.168.1.78 - - [12/Jan/2026:10:23:22 +0000] "POST /api/login HTTP/1.1" 200 245 "-" "Chrome/120.0"\n203.0.113.45 - - [12/Jan/2026:10:23:28 +0000] "GET /admin.php?id=1' OR 1=1-- HTTP/1.1" 404 0 "-" "sqlmap/1.7.2"\n172.16.0.5 - - [12/Jan/2026:10:23:25 +0000] "GET /dashboard HTTP/1.1" 200 8934 "-" "Firefox/121.0"\n192.168.1.45 - - [12/Jan/2026:10:23:30 +0000] "GET /about.html HTTP/1.1" 200 3421 "-" "Safari/17.0"`,
                malicious_line_index: 3,
                attack_type: 'SQL Injection',
                explanation: 'Contains SQL injection payload and suspicious sqlmap user agent'
              });
              setSelectedLine(3);
              toast.success('Sample logs loaded and malicious line selected.');
            }}
            className="px-4 py-2 bg-purple-500/20 border border-purple-500/40 text-purple-300 hover:bg-purple-500/30 rounded-lg text-sm font-semibold transition-all"
          >
            Load Sample Data
          </button>
          <button 
            onClick={reset} 
            disabled={loading}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Generating...
              </>
            ) : (
              'New Challenge'
            )}
          </button>
        </div>
      </div>

      <p className="text-slate-400 mb-6">
        Find the malicious request in these server logs. Look for SQL injection, scanning tools, or path traversal!
      </p>

      {loading ? (
        <div className="bg-slate-800/60 rounded-lg p-12 flex flex-col items-center justify-center">
          <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mb-4" />
          <p className="text-slate-400 text-center">
            🤖 AI is generating server logs...
            <br />
            <span className="text-sm text-slate-500">Injecting attack signature...</span>
          </p>
        </div>
      ) : challenge ? (
        <>
          <div className="bg-slate-800/60 rounded-lg p-4 mb-4 max-h-96 overflow-y-auto">
            {logLines.map((log, index) => (
              <div
                key={index}
                onClick={() => handleLineClick(index)}
                className={`font-mono text-xs p-2 cursor-pointer hover:bg-slate-700/60 rounded transition-colors ${
                  selectedLine === index ? 'bg-cyan-500/20 border-l-4 border-cyan-500' : ''
                } ${result === 'success' && index === challenge.malicious_line_index ? 'bg-green-500/20 border-l-4 border-green-500' : ''} ${
                  result === 'fail' && selectedLine === index ? 'bg-red-500/20 border-l-4 border-red-500' : ''
                }`}
              >
                <span className="text-slate-500 mr-2">{String(index + 1).padStart(2, '0')}</span>
                <span className="text-slate-300">{log}</span>
              </div>
            ))}
          </div>

          <button
            onClick={handleSubmit}
            disabled={selectedLine === null || result !== 'idle'}
            className="w-full py-3 bg-gradient-to-r from-yellow-500 to-orange-500 hover:from-yellow-600 hover:to-orange-600 text-white font-semibold rounded-lg transition-all disabled:opacity-50"
          >
            Submit Answer
          </button>

          {result === 'success' && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="mt-4 p-4 bg-green-500/10 border border-green-500/30 rounded-lg"
            >
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <span className="text-green-400 font-semibold">Correct! +40 points 🎯</span>
              </div>
              <div className="text-sm text-slate-300">
                <strong>Attack Type:</strong> {challenge.attack_type}
                <br />
                <strong>Explanation:</strong> {challenge.explanation}
              </div>
            </motion.div>
          )}

          {result === 'fail' && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg"
            >
              <div className="flex items-center gap-2">
                <XCircle className="w-5 h-5 text-red-400" />
                <span className="text-red-400 font-semibold">Wrong line. Look for scanning tools, injection attempts, or suspicious paths!</span>
              </div>
            </motion.div>
          )}
        </>
      ) : null}
    </div>
  );
}

// ==================== Game 5: Auto-Pentest Staging ====================
function PentestSimulation({ onScore }: { onScore: (points: number) => void }) {
  const [challenge, setChallenge] = useState<PentestChallenge | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<'idle' | 'running' | 'success'>('idle');
  const [terminalLog, setTerminalLog] = useState<string[]>([]);

  const loadNewChallenge = async () => {
    setLoading(true);
    setResult('idle');
    setTerminalLog([]);
    try {
      const newChallenge = await generateDojoChallenge('pentest') as PentestChallenge;
      setChallenge(newChallenge);
    } catch (error) {
      console.error('Error generating pentest challenge:', error);
      toast.error('Challenge generation unavailable. Loaded fallback scenario.');
    }
    setLoading(false);
  };

  useEffect(() => {
    loadNewChallenge();
  }, []);

  const handleLaunch = () => {
    if (!challenge) return;
    setResult('running');
    setTerminalLog(['[+] Initializing container staging environment...', '[+] Target: ' + challenge.targetEnvironment, '[+] Injecting exploit script...']);

    let step = 0;
    const lines = challenge.exploitScript.split('\n').filter(l => l.trim() !== '');
    
    const interval = setInterval(() => {
      if (step < lines.length) {
        setTerminalLog(prev => [...prev, '$ ' + lines[step]]);
        step++;
      } else {
        clearInterval(interval);
        setTimeout(() => {
          setTerminalLog(prev => [...prev, '', '[!] EXPLOIT SUCCESSFUL. Root access achieved.']);
          setResult('success');
          onScore(50);
        }, 1000);
      }
    }, 600);
  };

  return (
    <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-cyan-400" />
          Auto-Pentest Staging
          {challenge && (
            <span className="text-sm font-normal text-slate-400">- Containerized Exploit Sandbox</span>
          )}
        </h2>
        <div className="flex gap-2">
          <button
            onClick={() => {
              setChallenge({
                targetEnvironment: 'Staging App Node Container (IP: 10.0.12.3)',
                vulnerability: 'CVE-2024-6387 (regreSSHion)',
                exploitScript: 'nmap -sV -p 22 10.0.12.3\npython3 exploit_cve_2024_6387.py --ip 10.0.12.3\nwhoami\ncat /etc/passwd',
                mitigationSteps: [
                  'Upgrade OpenSSH to version 9.8p1 or newer.',
                  'Limit SSH port access via iptables or security group policies.',
                  'Configure LoginGraceTime to 0 in sshd_config (temporary workaround).'
                ],
                difficulty: 'hard'
              });
              toast.success('Sample Pentest scenario loaded.');
            }}
            className="px-4 py-2 bg-purple-500/20 border border-purple-500/40 text-purple-300 hover:bg-purple-500/30 rounded-lg text-sm font-semibold transition-all"
          >
            Load Sample Data
          </button>
          <button 
            onClick={loadNewChallenge} 
            disabled={loading || result === 'running'}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Staging...
              </>
            ) : (
              'Load New Scenario'
            )}
          </button>
        </div>
      </div>

      <p className="text-slate-400 mb-6">
        Simulate real-world attacks. Generate an exploit script for a specific CVE and test it in a containerized environment to understand its impact and how to mitigate it.
      </p>

      {loading ? (
        <div className="bg-slate-800/60 rounded-lg p-12 flex flex-col items-center justify-center">
          <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mb-4" />
          <p className="text-slate-400 text-center">
            🤖 AI is spinning up the sandbox container...
            <br />
            <span className="text-sm text-slate-500">Preparing vulnerability vector...</span>
          </p>
        </div>
      ) : challenge ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
              <h3 className="text-white font-semibold mb-2">Target Environment</h3>
              <p className="text-slate-400 text-sm">{challenge.targetEnvironment}</p>
            </div>
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <h3 className="text-red-400 font-semibold mb-2 flex items-center gap-2">
                <Target className="w-4 h-4" /> Selected Vulnerability
              </h3>
              <p className="text-red-300 text-sm font-mono">{challenge.vulnerability}</p>
            </div>
            
            <button
              onClick={handleLaunch}
              disabled={result !== 'idle'}
              className="w-full py-4 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold rounded-lg transition-all shadow-lg shadow-red-500/30 disabled:opacity-50"
            >
              {result === 'idle' ? 'Launch Exploit Simulation' : result === 'running' ? 'Executing Exploit...' : 'Exploit Deployed'}
            </button>
            
            {result === 'success' && (
               <motion.div
                 initial={{ opacity: 0, scale: 0.95 }}
                 animate={{ opacity: 1, scale: 1 }}
                 className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg"
               >
                 <div className="flex items-center gap-2 mb-2">
                   <CheckCircle className="w-5 h-5 text-green-400" />
                   <span className="text-green-400 font-semibold">Simulation Complete (+50 points)</span>
                 </div>
                 <div className="text-sm text-slate-300">
                   <strong>Required Mitigations:</strong>
                   <ul className="list-disc list-inside mt-1 space-y-1">
                     {challenge.mitigationSteps.map((step, i) => (
                       <li key={i}>{step}</li>
                     ))}
                   </ul>
                 </div>
               </motion.div>
            )}
          </div>

          <div className="bg-slate-900 border border-slate-700/50 rounded-lg p-4 flex flex-col font-mono text-sm shadow-inner relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-8 bg-slate-800 border-b border-slate-700 flex items-center px-4">
              <span className="text-slate-400 text-xs">root@sandbox:~</span>
            </div>
            <div className="flex-1 mt-6 overflow-y-auto space-y-1">
              {terminalLog.length === 0 ? (
                <div className="text-slate-500 italic mt-2">Waiting for exploit execution...</div>
              ) : (
                terminalLog.map((line, idx) => (
                  <div key={idx} className={line.startsWith('[!]') ? 'text-red-400 font-bold' : line.startsWith('[+]') ? 'text-cyan-400' : 'text-slate-300'}>
                    {line}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

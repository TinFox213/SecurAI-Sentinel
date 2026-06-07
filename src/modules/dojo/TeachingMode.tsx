import React from 'react';
import { motion } from 'framer-motion';
import { BookOpen, X, Lightbulb, Target, Shield } from 'lucide-react';

interface TeachingModeProps {
  gameType: 'phishing' | 'sqli' | 'crypto' | 'loghunter' | 'pentest';
  onClose: () => void;
}

export default function TeachingMode({ gameType, onClose }: TeachingModeProps) {
  const tutorials = {
    phishing: {
      title: '🎯 Phishing Detective - Learn to Play',
      icon: Target,
      color: 'from-red-500 to-pink-500',
      sections: [
        {
          title: 'What is Phishing?',
          content: 'Phishing is a cyber attack where attackers impersonate trusted entities to steal sensitive information like passwords, credit cards, or personal data.',
          tip: '🔍 Always verify the sender before clicking any links!'
        },
        {
          title: 'How to Play',
          content: 'You\'ll receive fake emails. Your job is to identify ALL suspicious elements by clicking on them. Each email contains 3-5 red flags.',
          tip: '🎮 Click on suspicious text in the email to mark it'
        },
        {
          title: 'What to Look For',
          content: '• Suspicious domains (paypa1.com instead of paypal.com)\n• Urgent language ("Act now or lose access!")\n• Grammar/spelling mistakes\n• Unusual requests (asking for passwords)\n• Generic greetings ("Dear Customer")',
          tip: '⚠️ Real companies never ask for passwords via email'
        },
        {
          title: 'Scoring',
          content: '• Find all red flags: +10 points\n• Miss some flags: -2 points\n• Click wrong text: -1 point\n\nNew Challenge button generates a fresh email to practice!',
          tip: '🏆 Aim for 50+ points to become a master detective!'
        }
      ]
    },
    sqli: {
      title: '💉 SQL Injection Playground - Learn to Play',
      icon: Shield,
      color: 'from-blue-500 to-cyan-500',
      sections: [
        {
          title: 'What is SQL Injection?',
          content: 'SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in database queries to access or manipulate data.',
          tip: '⚠️ Never trust user input without validation!'
        },
        {
          title: 'How to Play',
          content: 'Type SQL injection payloads into the search box to bypass authentication or extract data. Try classic techniques like OR 1=1, UNION SELECT, or comment tricks.',
          tip: '🎮 Experiment with different payloads to learn'
        },
        {
          title: 'Common Payloads to Try',
          content: '• \' OR 1=1-- (bypass login)\n• admin\'-- (comment out password check)\n• \' UNION SELECT * FROM users-- (extract data)\n• \'; DROP TABLE users;-- (dangerous!)',
          tip: '🔐 In real apps, ALWAYS use parameterized queries'
        },
        {
          title: 'Learning Goal',
          content: 'Understanding SQLi helps you write secure code. Always sanitize inputs, use prepared statements, and never concatenate user input into SQL queries.',
          tip: '🛡️ Defense > Offense - Learn to protect, not exploit'
        }
      ]
    },
    crypto: {
      title: '🔐 Crypto Cracker - Learn to Play',
      icon: Lightbulb,
      color: 'from-purple-500 to-pink-500',
      sections: [
        {
          title: 'What is Cryptography?',
          content: 'Cryptography is the practice of securing information by transforming it into an unreadable format. Decryption reverses this process.',
          tip: '🔑 Strong encryption protects our digital world'
        },
        {
          title: 'How to Play',
          content: 'You\'ll see encrypted text in Base64 or Hexadecimal format. Decode it to reveal the hidden flag. Use the hint to identify the encoding type.',
          tip: '🎮 Click "Decode Base64" or "Decode Hex" buttons'
        },
        {
          title: 'Encoding Types',
          content: '• Base64: Uses A-Z, a-z, 0-9, +, / characters\n  Example: RkxBR3tURVNUfQ==\n\n• Hexadecimal: Uses 0-9 and A-F characters\n  Example: 464c41477b544553547d',
          tip: '🔍 Look for = padding in Base64, pairs of chars in Hex'
        },
        {
          title: 'Real-World Use',
          content: 'Encoding (Base64/Hex) is NOT encryption - it\'s just representation. Real security uses AES, RSA, or other strong algorithms with keys.',
          tip: '⚠️ Never use Base64 to "hide" sensitive data!'
        }
      ]
    },
    loghunter: {
      title: '📋 Log Hunter - Learn to Play',
      icon: Target,
      color: 'from-green-500 to-emerald-500',
      sections: [
        {
          title: 'What are Server Logs?',
          content: 'Server logs record every request made to a web application. They\'re crucial for detecting attacks, debugging, and monitoring.',
          tip: '📊 Logs are your security camera footage'
        },
        {
          title: 'How to Play',
          content: 'Scan through Apache access logs to find the ONE malicious entry hidden among normal traffic. Look for suspicious patterns in URLs, user agents, or status codes.',
          tip: '🎮 Click on the log line you think is malicious'
        },
        {
          title: 'Attack Signatures to Spot',
          content: '• SQL injection attempts: \' OR 1=1--\n• Path traversal: ../../etc/passwd\n• Admin panel probing: /admin.php, /phpmyadmin\n• Automated tools: sqlmap, nikto, curl\n• Unusual status codes: 404 on sensitive paths',
          tip: '🔍 Normal logs show 200 status, browsers, common paths'
        },
        {
          title: 'Security Operations',
          content: 'Real SOC analysts review thousands of logs daily. Tools like SIEM systems help automate detection, but human analysis is irreplaceable.',
          tip: '🛡️ Log analysis is a critical security skill'
        }
      ]
    },
    pentest: {
      title: '⚡ Auto-Pentest Simulator - Learn to Play',
      icon: Target,
      color: 'from-orange-500 to-red-500',
      sections: [
        {
          title: 'What is Penetration Testing?',
          content: 'Penetration testing simulates real-world cyberattacks on a system to identify and remediate security vulnerabilities before malicious hackers can exploit them.',
          tip: '🔍 Think like an attacker, defend like a professional.'
        },
        {
          title: 'How to Play',
          content: 'The AI will generate a vulnerable containerized staging environment based on a specific CVE (vulnerability). Your goal is to launch the exploit and analyze the execution flow.',
          tip: '🎮 Click "Launch Exploit Simulation" to start the attack sequence.'
        },
        {
          title: 'What to Look For',
          content: '• Analyze the generated Bash/Python script logic.\n• Watch the terminal output line-by-line as the exploit progresses.\n• Review the required Mitigation steps once root access is achieved.',
          tip: '⚠️ Understanding the exploit is key to writing the patch!'
        }
      ]
    }
  };

  const tutorial = tutorials[gameType];

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-6"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.9, y: 20 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.9, y: 20 }}
        onClick={(e) => e.stopPropagation()}
        className="bg-slate-900 border border-white/20 rounded-3xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
      >
        {/* Header */}
        <div className={`bg-gradient-to-r ${tutorial.color} p-6 rounded-t-3xl`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-white/20 rounded-xl">
                <tutorial.icon className="w-8 h-8 text-white" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">{tutorial.title}</h2>
                <p className="text-white/80 text-sm">Master the game in 2 minutes</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/20 rounded-xl transition-colors"
            >
              <X className="w-6 h-6 text-white" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {tutorial.sections.map((section, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-slate-800/60 border border-white/10 rounded-2xl p-5"
            >
              <h3 className="text-xl font-bold text-white mb-3 flex items-center gap-2">
                <span className={`bg-gradient-to-r ${tutorial.color} bg-clip-text text-transparent`}>
                  {index + 1}.
                </span>
                {section.title}
              </h3>
              <p className="text-slate-300 whitespace-pre-line mb-4 leading-relaxed">
                {section.content}
              </p>
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 flex items-start gap-2">
                <Lightbulb className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                <p className="text-yellow-300 text-sm">{section.tip}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-white/10 bg-slate-800/40">
          <button
            onClick={onClose}
            className={`w-full bg-gradient-to-r ${tutorial.color} text-white font-bold py-4 rounded-xl hover:shadow-lg hover:shadow-cyan-500/50 transition-all`}
          >
            Got it! Let's Play 🎮
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

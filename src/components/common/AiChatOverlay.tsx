import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageCircle, X, Send, Loader2, Sparkles } from 'lucide-react';
import { SecurityAnalysis } from '../../types/types';

interface AiChatOverlayProps {
  analysisContext?: SecurityAnalysis;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

const AiChatOverlay: React.FC<AiChatOverlayProps> = ({ analysisContext }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const suggestedPrompts = [
    "Analyze the last scan results",
    "What are the critical risks here?",
    "Explain the remediation steps",
    "Generate a Python patch script",
    "Show me the attack chain",
    "How urgent is this threat?"
  ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (isOpen && analysisContext && messages.length === 0) {
      setMessages([{
        role: 'assistant',
        content: `I'm your AI security assistant. I have context of your recent ${analysisContext.threat_level} threat analysis with a risk score of ${analysisContext.risk_score}/100. Ask me anything about the findings or how to remediate them!`,
        timestamp: new Date()
      }]);
      setShowSuggestions(true);
    }
  }, [isOpen, analysisContext, messages.length]);

  const handleSend = async (customInput?: string) => {
    const messageText = customInput || input;
    if (!messageText.trim() || loading) return;

    const userMessage: Message = {
      role: 'user',
      content: messageText,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);
    setShowSuggestions(false);

    try {
      // Use backend proxy instead of direct API call
      const response = await fetch('http://localhost:3001/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: messageText,
          context: analysisContext
        })
      });

      if (!response.ok) {
        throw new Error('Chat request failed');
      }

      const data = await response.json();
      
      const assistantMessage: Message = {
        role: 'assistant',
        content: data.response || 'I apologize, but I could not generate a response.',
        timestamp: new Date()
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch {
      const errorMessage: Message = {
        role: 'assistant',
        content: 'Sorry, I encountered an error processing your request. Please try again.',
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickAction = (prompt: string) => {
    setShowSuggestions(false);
    void handleSend(prompt);
  };

  return (
    <>
      {/* Floating Button */}
      <AnimatePresence>
        {!isOpen && (
          <motion.button
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            onClick={() => setIsOpen(true)}
            className="fixed bottom-6 right-6 w-14 h-14 bg-cyan-600 hover:bg-cyan-500 text-white rounded-full shadow-lg shadow-cyan-500/50 hover:shadow-cyan-500/70 flex items-center justify-center transition-all z-50"
          >
            <MessageCircle className="w-6 h-6" />
          </motion.button>
        )}
      </AnimatePresence>

      {/* Chat Panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            className="fixed bottom-6 right-6 w-96 h-[500px] bg-slate-900/80 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl flex flex-col z-50"
          >
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-white/10">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-slate-100">AI Security Assistant</h3>
              </div>
              <button
                onClick={() => setIsOpen(false)}
                className="text-slate-400 hover:text-slate-200 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* Quick Action Chips */}
              {showSuggestions && messages.length > 0 && analysisContext && (
                <div className="mb-4 pb-4 border-b border-white/10">
                  <p className="text-xs text-slate-500 mb-2 uppercase tracking-wider">Suggested Questions</p>
                  <div className="flex gap-2 overflow-x-auto pb-2 scrollbar-hide">
                    {suggestedPrompts.map((prompt) => (
                      <button
                        key={prompt}
                        onClick={() => handleQuickAction(prompt)}
                        className="flex-shrink-0 px-3 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 rounded-full text-xs font-medium transition-all border border-cyan-500/20 whitespace-nowrap"
                      >
                        {prompt}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {messages.map((msg, idx) => (
                <div
                  key={`${msg.timestamp.getTime()}-${idx}`}
                  className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <div
                    className={`max-w-[80%] p-3 rounded-lg text-sm ${
                      msg.role === 'user'
                        ? 'bg-cyan-600 text-white'
                        : 'bg-slate-800/60 backdrop-blur-sm text-slate-200 border border-white/5'
                    }`}
                  >
                    {msg.content}
                  </div>
                </div>
              ))}
              {loading && (
                <div className="flex justify-start">
                  <div className="bg-slate-800/60 backdrop-blur-sm p-3 rounded-lg border border-white/5">
                    <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="p-4 border-t border-white/10">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      void handleSend();
                    }
                  }}
                  placeholder="Ask about the analysis..."
                  className="flex-1 bg-slate-950/50 text-slate-200 px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/50 border border-white/5"
                  disabled={loading}
                />
                <button
                  onClick={() => handleSend()}
                  disabled={loading || !input.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded-lg transition-colors"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default AiChatOverlay;

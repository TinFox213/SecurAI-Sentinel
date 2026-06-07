import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, X, Siren } from 'lucide-react';

interface CanaryAlert {
  type: string;
  timestamp: string;
  ip: string;
  userAgent: string;
  token: string;
  referer: string;
  severity: string;
}

export default function LiveAlertToast() {
  const [alerts, setAlerts] = useState<CanaryAlert[]>([]);
  const [visibleAlerts, setVisibleAlerts] = useState<CanaryAlert[]>([]);
  const alertCountRef = useRef(0);
  const hideTimeoutsRef = useRef<number[]>([]);

  const getAlertId = (alert: CanaryAlert) => `${alert.timestamp}-${alert.token}`;

  useEffect(() => {
    alertCountRef.current = alerts.length;
  }, [alerts.length]);

  useEffect(() => {
    let isMounted = true;

    const pollAlerts = async () => {
      try {
        const response = await fetch('http://localhost:3001/canary-alerts');
        const data = await response.json();

        if (!isMounted || !data.success || !Array.isArray(data.alerts)) {
          return;
        }

        const previousCount = alertCountRef.current;
        const currentAlerts: CanaryAlert[] = data.alerts;

        if (currentAlerts.length > previousCount) {
          const newAlerts = currentAlerts.slice(previousCount);
          setAlerts(currentAlerts);
          alertCountRef.current = currentAlerts.length;

          newAlerts.forEach((alert: CanaryAlert) => {
            setVisibleAlerts((prev) => [...prev, alert]);

            const timeoutId = window.setTimeout(() => {
              setVisibleAlerts((prev) => prev.filter((a) => getAlertId(a) !== getAlertId(alert)));
            }, 8000);
            hideTimeoutsRef.current.push(timeoutId);
          });
        } else if (currentAlerts.length !== previousCount) {
          setAlerts(currentAlerts);
          alertCountRef.current = currentAlerts.length;
        }
      } catch {
        // Server not available - silently fail.
      }
    };

    const pollInterval = window.setInterval(() => {
      void pollAlerts();
    }, 2000);

    void pollAlerts();

    return () => {
      isMounted = false;
      window.clearInterval(pollInterval);
      hideTimeoutsRef.current.forEach((timeoutId) => window.clearTimeout(timeoutId));
      hideTimeoutsRef.current = [];
    };
  }, []);

  const dismissAlert = (timestamp: string) => {
    setVisibleAlerts((prev) => prev.filter((a) => a.timestamp !== timestamp));
  };

  return (
    <div className="fixed top-6 right-6 z-50 space-y-3 pointer-events-none">
      <AnimatePresence>
        {visibleAlerts.map((alert) => (
          <motion.div
            key={getAlertId(alert)}
            initial={{ opacity: 0, x: 300, scale: 0.8 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 300, scale: 0.8 }}
            className="pointer-events-auto bg-gradient-to-r from-red-600 to-orange-600 backdrop-blur-xl border-2 border-red-400/50 rounded-xl shadow-2xl shadow-red-500/50 p-4 max-w-md"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-3 flex-1">
                <div className="p-2 bg-white/20 rounded-lg animate-pulse">
                  <Siren className="w-6 h-6 text-white" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <AlertTriangle className="w-5 h-5 text-yellow-300" />
                    <h3 className="font-bold text-white text-lg">
                      CANARY TRAP TRIGGERED
                    </h3>
                  </div>
                  <div className="space-y-1 text-sm text-white/90">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">IP:</span>
                      <span className="font-mono bg-black/30 px-2 py-0.5 rounded">{alert.ip}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">Token:</span>
                      <span className="font-mono bg-black/30 px-2 py-0.5 rounded text-xs truncate max-w-[200px]">
                        {alert.token}
                      </span>
                    </div>
                    <div className="text-xs text-white/70 mt-2">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              </div>
              <button
                onClick={() => dismissAlert(alert.timestamp)}
                className="p-1 hover:bg-white/20 rounded-lg transition-colors"
                title="Dismiss alert"
              >
                <X className="w-5 h-5 text-white" />
              </button>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

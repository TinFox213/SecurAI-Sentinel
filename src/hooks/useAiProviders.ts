import { useEffect, useState } from 'react';
import {
  AiProviderStatus,
  fetchAiProviderStatus,
  offlineAiProviderStatus,
} from '../services/aiProviderService';

export function useAiProviders(refreshMs = 30000) {
  const [status, setStatus] = useState<AiProviderStatus>(offlineAiProviderStatus);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    let intervalId: number | undefined;

    const load = async () => {
      const nextStatus = await fetchAiProviderStatus();
      if (!active) return;
      setStatus(nextStatus);
      setLoading(false);
    };

    load();
    if (refreshMs > 0) {
      intervalId = window.setInterval(load, refreshMs);
    }

    return () => {
      active = false;
      if (intervalId) window.clearInterval(intervalId);
    };
  }, [refreshMs]);

  return { status, loading };
}

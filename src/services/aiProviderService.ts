export interface AiProviderInfo {
  id: string;
  label: string;
  model: string;
  configured: boolean;
  selected: boolean;
  priority: number;
}

export interface AiProviderStatus {
  mode: string;
  configuredCount: number;
  totalCount: number;
  activeProvider: string | null;
  providers: AiProviderInfo[];
  healthy: boolean;
  message: string;
}

export const offlineAiProviderStatus: AiProviderStatus = {
  mode: 'offline',
  configuredCount: 0,
  totalCount: 3,
  activeProvider: null,
  providers: [],
  healthy: false,
  message: 'Backend unavailable',
};

export async function fetchAiProviderStatus(): Promise<AiProviderStatus> {
  try {
    const response = await fetch('http://localhost:3001/api/ai-providers');
    if (!response.ok) {
      throw new Error(`Provider status failed (${response.status})`);
    }
    return await response.json();
  } catch {
    return offlineAiProviderStatus;
  }
}

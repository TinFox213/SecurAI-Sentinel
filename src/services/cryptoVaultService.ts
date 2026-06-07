import { AutoRemediationResult } from "../types/types";

// Schema definitions removed - now handled via backend proxy

export const analyzeAndFixCode = async (
  fileName: string,
  fileContent: string
): Promise<AutoRemediationResult> => {
  try {
    const response = await fetch('http://localhost:3001/api/analyze-code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fileName,
        fileContent
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Analysis failed' }));
      throw new Error(errorData.message || 'Code analysis request failed');
    }

    const result: AutoRemediationResult = await response.json();
    return result;
    
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Failed to analyze code';
    console.error('Code Analysis Error:', error);
    throw new Error(message);
  }
};

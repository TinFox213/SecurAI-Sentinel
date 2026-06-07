import { ForensicsEvent } from '../types/types';
import { saveForensicsEvent, saveSetting } from '../services/db';

export async function logForensicsEvent(event: Omit<ForensicsEvent, 'id' | 'isBookmarked'>): Promise<void> {
  try {
    const id = crypto.randomUUID();
    const fullEvent: ForensicsEvent = {
      id,
      isBookmarked: false,
      ...event
    };

    await saveForensicsEvent(fullEvent);
    await saveSetting(`forensics_event_${event.timestamp}`, fullEvent);
  } catch (error) {
    // Never block caller modules on forensic logging failures.
    console.error('Forensics logging failed:', error);
  }
}

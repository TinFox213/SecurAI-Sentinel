import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
  plugins: [react()],
  // Removed API key injection - now handled securely via backend proxy
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    }
  }
});

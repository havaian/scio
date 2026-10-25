import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    port: 5173,
    // Dev only: forward /api to the NestJS backend.
    proxy: { '/api': process.env.API_URL ?? 'http://localhost:3000' },
  },
  preview: {
    port: 4173,
    proxy: { '/api': process.env.API_URL ?? 'http://localhost:3000' },
  },
});

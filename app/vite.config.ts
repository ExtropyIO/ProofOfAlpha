import path from 'path'
import { fileURLToPath } from 'url'
import { defineConfig } from 'vite'
import type { Plugin } from 'vite'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// Rewrite CRS URL in @aztec/bb.js so proof generation uses a reliable CDN (works in dev, build, and workers).
function crsUrlRewritePlugin(): Plugin {
  const crsHost = 'https://crs.aztec.network'
  const crsCdn = 'https://crs.aztec-cdn.foundation'
  return {
    name: 'crs-url-rewrite',
    transform(code: string, id: string) {
      if (id.includes('@aztec/bb.js') && id.includes('net_crs') && code.includes(crsHost)) {
        return { code: code.replaceAll(crsHost, crsCdn), map: null }
      }
    },
  }
}

import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    crsUrlRewritePlugin(),
    react(),
    nodePolyfills({
      // Enable polyfills for Buffer and other Node.js globals
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      protocolImports: true,
    }),
  ],
  worker: {
    format: 'es',
    plugins: () => [
      crsUrlRewritePlugin(),
      nodePolyfills({
        globals: {
          Buffer: true,
          global: true,
          process: true,
        },
        protocolImports: true,
      }),
    ],
  },
  resolve: {
    alias: {
      // Fix for pino browser compatibility
      pino: 'pino/browser.js',
      // Use CRS fallback (tries crs.aztec-cdn.foundation, crs.aztec-labs.com, then crs.aztec.network).
      // Default crs.aztec.network is often unreachable and causes "Failed to fetch" during proof generation.
      [path.resolve(__dirname, 'node_modules/@aztec/bb.js/dest/browser/crs/net_crs.js')]: path.resolve(
        __dirname,
        'src/crs-net-fallback.ts'
      ),
    },
  },
  optimizeDeps: {
    exclude: ['@aztec/bb.js', '@noir-lang/noir_js', '@noir-lang/acvm_js'],
    include: ['pino'],
    esbuildOptions: {
      target: 'esnext',
    },
  },
  server: {
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  build: {
    commonjsOptions: {
      transformMixedEsModules: true,
    },
  },
})
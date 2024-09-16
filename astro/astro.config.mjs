import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
export default defineConfig({
  // ...
  integrations: [react()],
  site: 'https://xeonliu.github.io/nge_2_re/'
});
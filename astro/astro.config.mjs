import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import mdx from '@astrojs/mdx';
export default defineConfig({
  // ...
  integrations: [react(), mdx()],
  site: 'https://xeonliu.github.io',
  base: '/nge_2_re'
});
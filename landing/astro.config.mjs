// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Landing page at /, documentation at /docs/ (Starlight, content under
// src/content/docs/docs so every slug is prefixed).
export default defineConfig({
  site: 'https://nordyg.com',
  integrations: [
    starlight({
      title: 'Nordyg',
      description: 'A native macOS app for DNS: queries, DNSSEC, compare, trace, email and registry checks.',
      logo: { src: './public/logo-96.png', alt: 'Nordyg', replacesTitle: false },
      favicon: '/favicon.png',
      customCss: ['./src/styles/brand.css'],
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/n0rdy/nordyg' }],
      editLink: { baseUrl: 'https://github.com/n0rdy/nordyg/edit/main/landing/' },
      sidebar: [{ label: 'Documentation', items: [{ autogenerate: { directory: 'docs' } }] }],
    }),
  ],
});

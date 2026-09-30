import type { APIRoute } from 'astro';
export const GET: APIRoute = ({ site }) => new Response(site && import.meta.env.VERCEL_ENV !== 'preview' ? `User-agent: *\nAllow: /\nSitemap: ${new URL('/sitemap.xml', site)}\n` : 'User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

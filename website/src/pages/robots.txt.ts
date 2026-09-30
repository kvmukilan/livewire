import type { APIRoute } from 'astro';
import { sitePath } from '../data/site';
export const GET: APIRoute = ({ site }) => new Response(site && import.meta.env.VERCEL_ENV !== 'preview' ? `User-agent: *\nAllow: /\nSitemap: ${new URL(sitePath('/sitemap.xml'), site)}\n` : 'User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

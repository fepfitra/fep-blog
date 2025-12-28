import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import mdx from "@astrojs/mdx";
import pagefind from "astro-pagefind";
import tailwindcss from "@tailwindcss/vite";
import { typst } from 'astro-typst';


import cloudflare from "@astrojs/cloudflare";

// https://astro.build/config
export default defineConfig({
	site: "https://blog.fitrafep.com",
	integrations: [sitemap(), mdx(), typst({
		options: {
			remPx: 14,
		},
		target: (id) => {
			console.debug("Detected typst file:", id);
			return "html";
		}
	}), pagefind()],

	vite: {
		plugins: [tailwindcss()],
		ssr: {
			external: ["@myriaddreamin/typst-ts-node-compiler"]
		}
	},

	markdown: {
		shikiConfig: {
			theme: "css-variables",
		},
	},

	prefetch: true,

	adapter: cloudflare(),
});

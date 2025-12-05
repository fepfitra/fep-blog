
import { getCollection } from 'astro:content';

async function debug() {
    const modules = await getCollection('modules');
    console.log('--- Module IDs ---');
    modules.forEach(m => console.log(`ID: ${m.id}, File: ${m.filePath || 'unknown'}`));
    console.log('------------------');
}

debug();

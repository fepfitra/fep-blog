
import { getCollection } from 'astro:content';

async function debug() {
    const modules = await getCollection('modules');
    console.log('--- Module IDs ---');
    modules.forEach(m => console.log(m.id));
    console.log('------------------');
}

debug();

import type { CollectionEntry } from "astro:content";

export type ModuleNode = {
    _isDir: boolean;
    _children: Record<string, ModuleNode>;
    name?: string;
    id?: string;
    data?: CollectionEntry<"modules">["data"];
    collection?: "modules";
};

export function buildModuleTree(modules: CollectionEntry<"modules">[]) {
    const tree: Record<string, ModuleNode> = {};

    modules.forEach((module) => {
        const parts = module.id.split("/");
        let currentLevel: Record<string, ModuleNode> = tree;

        parts.forEach((part, index) => {
            if (!currentLevel[part]) {
                currentLevel[part] = {
                    _isDir: true,
                    _children: {},
                    name: part,
                };
            }

            if (index === parts.length - 1) {
                currentLevel[part] = {
                    ...currentLevel[part],
                    _isDir: false,
                    ...module,
                };
            } else {
                currentLevel = currentLevel[part]._children;
            }
        });
    });

    return tree;
}

export function sortModuleNodes(nodes: ModuleNode[]): ModuleNode[] {
    return nodes.sort((a, b) => {
        // 1. Index/Module files always first
        const aIsIndex = a.id?.endsWith("/module") || a.id?.endsWith("/index");
        const bIsIndex = b.id?.endsWith("/module") || b.id?.endsWith("/index");
        if (aIsIndex && !bIsIndex) return -1;
        if (!aIsIndex && bIsIndex) return 1;

        // 2. Files before Directories
        if (!a._isDir && b._isDir) return -1;
        if (a._isDir && !b._isDir) return 1;

        // 3. Sort by Order
        const aOrder = a.data?.order || 0;
        const bOrder = b.data?.order || 0;
        if (aOrder !== bOrder) {
            return aOrder - bOrder;
        }

        // 4. Alphabetical by title/name
        const aName = a.data?.title || a.name || "";
        const bName = b.data?.title || b.name || "";
        return aName.localeCompare(bName);
    });
}

export function flattenModuleTree(nodes: ModuleNode[]): ModuleNode[] {
    let result: ModuleNode[] = [];

    const sorted = sortModuleNodes(nodes);

    for (const node of sorted) {
        if (!node._isDir && node.id) {
            result.push(node);
        }

        if (node._children) {
            const children = Object.values(node._children);
            result = result.concat(flattenModuleTree(children));
        }
    }

    return result;
}

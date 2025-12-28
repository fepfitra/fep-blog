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
        let currentPath = "";

        parts.forEach((part, index) => {
            currentPath = currentPath ? `${currentPath}/${part}` : part;

            if (!currentLevel[part]) {
                currentLevel[part] = {
                    _isDir: true,
                    _children: {},
                    name: part,
                    id: currentPath,
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

    // Post-process: merge index/module files into parent directory nodes
    function mergeIndexNodes(nodes: Record<string, ModuleNode>, isTopLevel = false) {
        for (const key in nodes) {
            const node = nodes[key];
            if (node._children) {
                mergeIndexNodes(node._children, false);

                if (isTopLevel) continue; // Skip merging for top-level categories

                // Check for module or index child
                const indexKey = Object.keys(node._children).find(
                    (k) => k === "module" || k === "index"
                );

                if (indexKey) {
                    const indexNode = node._children[indexKey];
                    // Merge index node data into parent
                    node.data = indexNode.data;
                    node.id = indexNode.id;
                    node.collection = indexNode.collection;
                    // Remove the index node from children so it's not listed twice
                    delete node._children[indexKey];
                }
            }
        }
    }

    mergeIndexNodes(tree, true);

    return tree;
}

export function sortModuleNodes(nodes: ModuleNode[]): ModuleNode[] {
    return nodes.sort((a, b) => {
        // 1. Index/Module files always first
        const aIsIndex = a.id?.endsWith("/module") || a.id?.endsWith("/index");
        const bIsIndex = b.id?.endsWith("/module") || b.id?.endsWith("/index");
        if (aIsIndex && !bIsIndex) return -1;
        if (!aIsIndex && bIsIndex) return 1;

        // 2. Sort by Order
        const aOrder = a.data?.order ?? 999;
        const bOrder = b.data?.order ?? 999;
        if (aOrder !== bOrder) {
            return aOrder - bOrder;
        }

        // 3. Files before Directories (if order is same)
        if (!a._isDir && b._isDir) return -1;
        if (a._isDir && !b._isDir) return 1;

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
        // Include node if it has data and an id (represents a page)
        if (node.id && node.data) {
            result.push(node);
        }

        if (node._children) {
            const children = Object.values(node._children);
            result = result.concat(flattenModuleTree(children));
        }
    }

    return result;
}

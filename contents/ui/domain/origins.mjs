// Dependency provenance: names, normalized chains and grouping keys.

function arrayOf(value) {
    return Array.isArray(value) ? value : [];
}

export function namesOf(finding) {
    const origins = finding && finding.origins ? finding.origins : null;
    const names = origins ? origins.introduced_by : null;
    return Array.isArray(names) ? names : [];
}

export function primaryOf(finding) {
    const names = namesOf(finding);
    return names.length > 0 ? names[0] : "";
}

export function chainsOf(finding) {
    const origins = finding && finding.origins ? finding.origins : null;
    const chains = origins ? origins.chains : null;
    return Array.isArray(chains) ? chains : [];
}

export function storePathsOf(finding) {
    const origins = finding && finding.origins ? finding.origins : null;
    const paths = origins ? origins.store_paths : null;
    return Array.isArray(paths) ? paths : [];
}

// The backend may repeat a node and may append a version/output suffix to the
// vulnerable package. Normalize both so the row and the group remain readable.
export function normalizedChain(finding) {
    const origins = finding && finding.origins ? finding.origins : null;
    const chain = origins ? origins.chain : null;
    if (!Array.isArray(chain) || chain.length === 0) {
        return [];
    }

    const parts = [];
    for (let i = 0; i < chain.length; ++i) {
        const node = String(chain[i] || "");
        if (node.length === 0
                || (parts.length > 0 && parts[parts.length - 1] === node)) {
            continue;
        }
        parts.push(node);
    }

    if (finding && finding.package && finding.version && parts.length > 0) {
        const last = parts[parts.length - 1];
        if (last.indexOf(finding.package + "-") === 0
                && last.indexOf(finding.version) >= 0) {
            parts[parts.length - 1] = finding.package;
        }
    }

    if (parts.length > 1 && parts[parts.length - 1] === parts[parts.length - 2]) {
        parts.pop();
    }

    // A chain that only names the vulnerable package adds nothing to the
    // package cell above it.
    if (parts.length === 1 && finding && parts[0] === finding.package) {
        return [];
    }
    return parts;
}

export function chainText(finding) {
    return normalizedChain(finding).join(" → ");
}

const ORIGIN_OUTPUTS = "bin|data|debug|dev|doc|full|headless|info|lib|man|unwrapped|wrapper";
const ORIGIN_VERSION_RE = new RegExp(
    `(?:^|-)(\\d+\\.\\d+(?:\\.\\d+)*)(?=$|-(?:${ORIGIN_OUTPUTS}))`
);

/**
 * Split a chain node such as `ffmpeg-9.0.2-lib` into a display name and a
 * version. Output suffixes stay with the name: `ffmpeg` + `-lib` becomes
 * `ffmpeg-lib`, while the version is `9.0.2`.
 *
 * @param {string} node
 * @returns {{name: string, version: string}}
 */
export function splitNode(node) {
    const value = String(node || "");
    const match = ORIGIN_VERSION_RE.exec(value);
    if (!match) {
        return { name: value, version: "" };
    }
    const version = match[1];
    const prefix = value.slice(0, match.index);
    const suffix = value.slice(match.index + match[0].length);
    const name = (prefix + suffix).replace(/^-+/, "") || value;
    return { name, version };
}

export function groupKeyOf(finding) {
    return primaryOf(finding);
}

export function searchTextOf(finding) {
    const parts = [namesOf(finding).join(" "), chainText(finding)];

    // Filtering a trail chip must match rows whose path contains that step.
    // Index both the raw node and its version-less name, for every chain.
    const chains = chainsOf(finding);
    for (let c = 0; c < chains.length; ++c) {
        const chain = chains[c];
        if (!Array.isArray(chain)) {
            continue;
        }
        for (let i = 0; i < chain.length; ++i) {
            const node = String(chain[i] || "");
            if (node.length === 0) {
                continue;
            }
            parts.push(node);
            parts.push(splitNode(node).name);
        }
    }

    const normalized = normalizedChain(finding);
    for (let i = 0; i < normalized.length; ++i) {
        const node = normalized[i];
        if (node.length === 0) {
            continue;
        }
        parts.push(node);
        parts.push(splitNode(node).name);
    }

    return parts.join(" ");
}

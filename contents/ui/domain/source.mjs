// Package provenance: the flake source a finding's store path was built from.
//
// The backend writes one report-level source (the Nixpkgs channel and
// revision the scanned system was built from). A finding may carry its own
// `source` object later; the row uses that when present and falls back to the
// report. Keep this module dependency-free: the applet, the Node tests and the
// docs share the same shape.

function stringOf(value) {
    return value === null || value === undefined ? "" : String(value);
}

export function normalizeSource(raw) {
    if (raw === null || raw === undefined) {
        return null;
    }
    // A plain string is a display-ready label, useful for third-party
    // backends that already know how to describe their source.
    if (typeof raw === "string") {
        const label = raw.trim();
        return label.length > 0
            ? { flake: label, ref: "", rev: "", shortRev: "", label: label }
            : null;
    }
    if (typeof raw !== "object") {
        return null;
    }
    const flake = stringOf(raw.flake || raw.input);
    const ref = stringOf(raw.ref || raw.channel || raw.branch);
    const rev = stringOf(raw.rev);
    const shortRev = stringOf(raw.short_rev || raw.shortRev)
        || (rev.length > 7 ? rev.slice(0, 7) : rev);
    const label = stringOf(raw.label);
    if (!flake && !ref && !rev && !shortRev && !label) {
        return null;
    }
    return { flake: flake, ref: ref, rev: rev, shortRev: shortRev, label: label };
}

export function sourceNameText(source) {
    const normalized = normalizeSource(source);
    if (!normalized) {
        return "";
    }
    if (normalized.label) {
        return normalized.label;
    }
    if (normalized.flake && normalized.ref) {
        return normalized.flake + "/" + normalized.ref;
    }
    return normalized.flake || normalized.ref;
}

export function sourceRefText(source) {
    const normalized = normalizeSource(source);
    return normalized ? normalized.ref : "";
}

export function sourceRevLabel(source) {
    const normalized = normalizeSource(source);
    return normalized && normalized.shortRev
        ? "(" + normalized.shortRev + ")"
        : "";
}

export function sourceText(source) {
    const name = sourceNameText(source);
    const rev = sourceRevLabel(source);
    if (!name) {
        return rev;
    }
    return rev ? name + " " + rev : name;
}

export function sourceRevText(source) {
    const normalized = normalizeSource(source);
    return normalized ? normalized.rev : "";
}

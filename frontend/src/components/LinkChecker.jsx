import { useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const MAX_URL_LENGTH = 2048;
const MAX_BULK_LENGTH = 50000;

function sanitizeUrl(raw) {
    let url = raw.trim();
    /* eslint-disable-next-line no-control-regex */
    url = url.replace(/[\x00-\x1f\x7f]/g, "");
    if (/^(javascript|data|file|vbscript):/i.test(url)) return null;
    if (url.length > MAX_URL_LENGTH) return null;
    if (url && !url.startsWith("http://") && !url.startsWith("https://")) {
        url = "https://" + url;
    }
    try {
        const parsed = new URL(url);
        if (!["http:", "https:"].includes(parsed.protocol)) return null;
        if (!parsed.hostname) return null;
        return url;
    } catch {
        return null;
    }
}

function sanitizeBulkText(text) {
    return text.slice(0, MAX_BULK_LENGTH);
}

const Icons = {
    Shield: ({ className = "h-4 w-4" }) => (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
    ),
    Warning: ({ className = "h-4 w-4" }) => (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        </svg>
    ),
    Ban: ({ className = "h-4 w-4" }) => (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
    ),
    Check: ({ className = "h-4 w-4" }) => (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
    ),
    ChevronDown: ({ className = "h-4 w-4" }) => (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
    ),
    Sparkle: ({ className = "h-4 w-4" }) => (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
        </svg>
    ),
    Spinner: ({ className = "h-4 w-4" }) => (
        <svg className={`animate-spin ${className}`} fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
    ),
    Arrow: ({ className = "h-3 w-3" }) => (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
    ),
};

function getRiskConfig(riskLevel) {
    switch (riskLevel) {
        case "dangerous":
            return {
                gradient: "from-red-600/20 to-pink-600/20",
                border: "border-red-500/30",
                badge: "bg-gradient-to-r from-red-500/20 to-pink-500/20 text-red-200 border border-red-500/30",
                label: "DANGEROUS",
                icon: <Icons.Ban className="h-4 w-4" />,
            };
        case "suspicious":
            return {
                gradient: "from-amber-600/20 to-orange-600/20",
                border: "border-amber-500/30",
                badge: "bg-gradient-to-r from-amber-500/20 to-orange-500/20 text-amber-200 border border-amber-500/30",
                label: "SUSPICIOUS",
                icon: <Icons.Warning className="h-4 w-4" />,
            };
        default:
            return {
                gradient: "from-emerald-600/20 to-green-600/20",
                border: "border-emerald-500/30",
                badge: "bg-gradient-to-r from-emerald-500/20 to-green-500/20 text-emerald-200 border border-emerald-500/30",
                label: "SAFE",
                icon: <Icons.Check className="h-4 w-4" />,
            };
    }
}

function RiskBadge({ riskLevel }) {
    const cfg = getRiskConfig(riskLevel);
    return (
        <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold ${cfg.badge}`}>
            {cfg.icon}
            {cfg.label}
        </span>
    );
}

function StatusBadge({ isAlive, statusCode }) {
    if (isAlive) {
        return (
            <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-semibold bg-gradient-to-r from-blue-500/20 to-cyan-500/20 text-blue-200 border border-blue-500/30">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 inline-block animate-pulse" />
                {statusCode} OK
            </span>
        );
    }
    return (
        <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-semibold bg-slate-600/30 text-slate-300 border border-slate-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400 inline-block" />
            {statusCode || "No Response"}
        </span>
    );
}

function PhishingPanel({ phishing }) {
    const [expanded, setExpanded] = useState(false);
    if (!phishing) return null;

    const cfg = getRiskConfig(phishing.risk_level);
    const hasFlags = phishing.heuristic_flags?.length > 0;
    const hasGSB = phishing.safe_browsing_threat;
    const hasVT = phishing.virustotal_summary;

    return (
        <div className={`mt-4 rounded-xl border ${cfg.border} bg-gradient-to-br ${cfg.gradient} overflow-hidden`}>
            <button
                onClick={() => setExpanded(!expanded)}
                className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-all"
            >
                <div className="flex items-center gap-3">
                    <Icons.Shield className="h-4 w-4 text-slate-300" />
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-200">
                        Phishing Analysis
                    </span>
                    <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-slate-700/50 text-slate-300">
                        Score: {phishing.phishing_score ?? "—"}
                    </span>
                </div>
                <Icons.ChevronDown className={`h-4 w-4 text-slate-400 transition-transform ${expanded ? "rotate-180" : ""}`} />
            </button>

            {expanded && (
                <div className="px-4 py-4 space-y-3 bg-slate-800/30 border-t border-slate-600/30">
                    {hasGSB && (
                        <div className="flex items-start gap-3 p-3 rounded-lg bg-red-600/10 border border-red-500/30">
                            <Icons.Ban className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                            <div>
                                <p className="text-xs font-bold text-red-300">Google Safe Browsing</p>
                                <p className="text-xs text-red-400/80 mt-0.5">{phishing.safe_browsing_threat}</p>
                            </div>
                        </div>
                    )}

                    {hasVT && (
                        <div className={`flex items-start gap-3 p-3 rounded-lg border ${
                            phishing.virustotal_summary?.includes("malicious") || phishing.virustotal_summary?.includes("suspicious")
                                ? "bg-red-600/10 border-red-500/30"
                                : "bg-slate-600/10 border-slate-500/30"
                        }`}>
                            <Icons.Sparkle className="h-4 w-4 text-slate-400 mt-0.5 shrink-0" />
                            <div>
                                <p className="text-xs font-bold text-slate-300">VirusTotal</p>
                                <p className="text-xs text-slate-400 mt-0.5">{phishing.virustotal_summary}</p>
                            </div>
                        </div>
                    )}

                    {hasFlags ? (
                        <div>
                            <p className="text-xs font-bold text-slate-300 mb-2">Heuristic Flags ({phishing.heuristic_flags.length})</p>
                            <ul className="space-y-2">
                                {phishing.heuristic_flags.map((flag, i) => (
                                    <li key={i} className="text-xs px-3 py-2 rounded-lg flex items-start gap-2 bg-slate-700/50 text-slate-300 border border-slate-600/30">
                                        <span className="text-amber-400 mt-0.5 shrink-0">•</span>
                                        <span>{flag}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ) : (
                        <p className="text-xs text-slate-400 italic">No heuristic flags triggered.</p>
                    )}
                </div>
            )}
        </div>
    );
}

function ResultCard({ result }) {
    const riskLevel = result.phishing?.risk_level ?? "safe";
    const cfg = getRiskConfig(riskLevel);

    return (
        <div className={`rounded-xl border ${cfg.border} bg-gradient-to-br ${cfg.gradient} p-4 backdrop-blur-sm hover:border-slate-400/30 transition-all group`}>
            <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-slate-100 truncate font-medium group-hover:text-blue-300 transition-colors">{result.url}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                    {result.response_time_ms != null && (
                        <span className="text-xs text-slate-400">{result.response_time_ms}ms</span>
                    )}
                    <StatusBadge isAlive={result.is_alive} statusCode={result.status_code} />
                </div>
            </div>

            {result.redirect_url && (
                <p className="text-xs text-slate-400 mb-2 flex items-center gap-1">
                    <Icons.Arrow className="h-3 w-3 shrink-0" />
                    Redirected to: <span className="font-mono truncate text-slate-300">{result.redirect_url}</span>
                </p>
            )}

            {result.error && (
                <p className="text-xs text-red-400 mb-2 flex items-center gap-1">
                    <Icons.Warning className="h-3 w-3 shrink-0" />
                    {result.error}
                </p>
            )}

            <div className="mb-2">
                {result.phishing && <RiskBadge riskLevel={result.phishing.risk_level} />}
            </div>

            <PhishingPanel phishing={result.phishing} />

            {result.ai_analysis && (
                <div className="mt-4 p-3 rounded-lg bg-blue-600/10 border border-blue-500/30 text-xs text-blue-200 whitespace-pre-wrap leading-relaxed">
                    <p className="font-bold mb-2 flex items-center gap-1.5">
                        <Icons.Sparkle className="h-3.5 w-3.5" />
                        AI Analysis
                    </p>
                    {result.ai_analysis}
                </div>
            )}
        </div>
    );
}

function LinkChecker() {
    const [inputMode, setInputMode] = useState("manual");
    const [urls, setUrls] = useState([""]);
    const [bulkText, setBulkText] = useState("");
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState("");
    const [aiExpanded, setAiExpanded] = useState(false);

    const addUrl = () => {
        if (urls.length < 20) setUrls([...urls, ""]);
    };

    const updateUrl = (index, value) => {
        /* eslint-disable-next-line no-control-regex */
        const clean = value.replace(/[\x00-\x1f\x7f]/g, "");
        const updated = [...urls];
        updated[index] = clean.slice(0, MAX_URL_LENGTH);
        setUrls(updated);
    };

    const removeUrl = (index) => {
        setUrls(urls.filter((_, i) => i !== index));
    };

    const handleBulkTextChange = (e) => {
        setBulkText(sanitizeBulkText(e.target.value));
    };

    const runCheck = async (urlList) => {
        setLoading(true);
        setError("");

        const sanitized = urlList.map(sanitizeUrl).filter(Boolean);
        if (!sanitized.length) {
            setError("No valid URLs to check. Make sure URLs start with http:// or https://");
            setLoading(false);
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/check-links`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ urls: sanitized }),
            });
            if (res.status === 429) {
                setError("Too many requests. Please wait a moment and try again.");
                return;
            }
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Server error");
            }
            const data = await res.json();
            setResults(data);
            setAiExpanded(false);
        } catch (e) {
            setError(e.message || "Failed to connect to backend. Make sure it's running on port 8000.");
        } finally {
            setLoading(false);
        }
    };

    const handleExtractAndCheck = async () => {
        setLoading(true);
        setError("");
        try {
            const extractRes = await fetch(`${API_BASE}/extract-links`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text: bulkText }),
            });
            const extractData = await extractRes.json();
            if (!extractData.urls.length) {
                setError("No valid URLs found in the provided text.");
                setLoading(false);
                return;
            }
            await runCheck(extractData.urls);
        } catch {
            setError("Failed to connect to backend. Make sure it's running on port 8000.");
            setLoading(false);
        }
    };

    const handleManualCheck = async () => {
        const filtered = urls.filter((u) => u.trim());
        if (!filtered.length) {
            setError("Please enter at least one URL.");
            return;
        }
        await runCheck(filtered);
    };

    const handleReset = () => {
        setResults(null);
        setError("");
        setUrls([""]);
        setBulkText("");
        setAiExpanded(false);
    };

    const summary = results?.summary;

    return (
        <div className="min-h-[calc(100vh-4rem)] flex flex-col">
            <main id="home" className="max-w-5xl mx-auto px-4 py-12 w-full flex-1">
                <div className="text-center mb-12">
                    <h2 className="text-5xl md:text-6xl font-bold bg-gradient-to-r from-blue-300 via-blue-200 to-cyan-300 bg-clip-text text-transparent mb-4 animate-fade-in">
                        TrvstPulse
                    </h2>
                    <p className="text-lg text-slate-400 animate-fade-in">
                        Enterprise-grade link security analysis
                    </p>
                </div>

                <div className="flex gap-2 mb-8 justify-center">
                    {["manual", "bulk"].map((mode) => (
                        <button
                            key={mode}
                            onClick={() => setInputMode(mode)}
                            className={`px-6 py-2.5 rounded-lg font-semibold transition-all duration-200 ${
                                inputMode === mode
                                    ? "bg-gradient-to-r from-blue-600 to-blue-700 text-white shadow-lg shadow-blue-500/30"
                                    : "bg-slate-700/50 text-slate-400 hover:text-slate-300 border border-slate-600/30 hover:border-slate-500/30"
                            }`}
                        >
                            {mode === "manual" ? "Manual URLs" : "Bulk / Paste Text"}
                        </button>
                    ))}
                </div>

                <div className="glass-dark p-8 mb-8 animate-scale-in">
                    <label className="block text-sm font-semibold text-slate-200 mb-4">
                        {inputMode === "manual" ? "Enter URLs (max 20)" : "Paste any text"}
                    </label>

                    {inputMode === "manual" ? (
                        <div>
                            <div className="space-y-3 mb-4">
                                {urls.map((url, i) => (
                                    <div key={i} className="flex gap-2">
                                        <input
                                            type="url"
                                            value={url}
                                            onChange={(e) => updateUrl(i, e.target.value)}
                                            placeholder="https://example.com"
                                            maxLength={MAX_URL_LENGTH}
                                            className="input-modern flex-1"
                                            onKeyDown={(e) => e.key === "Enter" && addUrl()}
                                        />
                                        {urls.length > 1 && (
                                            <button
                                                onClick={() => removeUrl(i)}
                                                className="px-3 py-3 rounded-xl text-slate-400 hover:text-red-400 hover:bg-red-600/10 transition-all"
                                            >
                                                ×
                                            </button>
                                        )}
                                    </div>
                                ))}
                            </div>
                            <button
                                onClick={addUrl}
                                disabled={urls.length >= 20}
                                className="text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors disabled:opacity-40"
                            >
                                + Add URL
                            </button>
                        </div>
                    ) : (
                        <div>
                            <p className="text-xs text-slate-400 mb-3">
                                {bulkText.length}/{MAX_BULK_LENGTH} characters
                            </p>
                            <textarea
                                value={bulkText}
                                onChange={handleBulkTextChange}
                                maxLength={MAX_BULK_LENGTH}
                                placeholder="Paste HTML, markdown, emails, or any text containing URLs..."
                                className="input-modern h-48 resize-none"
                            />
                        </div>
                    )}

                    {error && (
                        <div className="mt-4 p-4 bg-red-600/10 border border-red-500/30 rounded-lg text-red-300 text-sm flex items-center gap-3 animate-scale-in">
                            <Icons.Warning className="h-4 w-4 shrink-0" />
                            {error}
                        </div>
                    )}

                    <div className="flex gap-3 mt-6">
                        <button
                            onClick={inputMode === "manual" ? handleManualCheck : handleExtractAndCheck}
                            disabled={loading}
                            className="btn-primary flex-1 flex items-center justify-center gap-2"
                        >
                            {loading ? (
                                <>
                                    <Icons.Spinner className="h-4 w-4" />
                                    Analyzing...
                                </>
                            ) : (
                                <>
                                    <Icons.Shield className="h-4 w-4" />
                                    Check Links
                                </>
                            )}
                        </button>
                        {results && (
                            <button onClick={handleReset} className="btn-secondary">
                                Reset
                            </button>
                        )}
                    </div>
                </div>

                {results && (
                    <div className="space-y-6 animate-fade-in">
                        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                            {[
                                { label: "Total", value: summary.total, gradient: "from-slate-600/20 to-slate-500/20", border: "border-slate-500/30" },
                                { label: "Alive", value: summary.alive, gradient: "from-emerald-600/20 to-green-600/20", border: "border-emerald-500/30" },
                                { label: "Broken", value: summary.dead, gradient: "from-slate-600/20 to-slate-500/20", border: "border-slate-500/30" },
                                { label: "Suspicious", value: summary.suspicious ?? 0, gradient: "from-amber-600/20 to-orange-600/20", border: "border-amber-500/30" },
                                { label: "Dangerous", value: summary.dangerous ?? 0, gradient: "from-red-600/20 to-pink-600/20", border: "border-red-500/30" },
                            ].map((stat, idx) => (
                                <div key={idx} className={`rounded-xl border ${stat.border} bg-gradient-to-br ${stat.gradient} p-4 text-center backdrop-blur-sm`}>
                                    <p className="text-3xl font-bold text-slate-100">{stat.value}</p>
                                    <p className="text-xs text-slate-400 font-medium mt-2 uppercase tracking-wider">{stat.label}</p>
                                </div>
                            ))}
                        </div>

                        {(summary.dangerous > 0 || summary.suspicious > 0) && (
                            <div className={`p-4 rounded-xl border backdrop-blur-sm flex items-start gap-3 ${
                                summary.dangerous > 0
                                    ? "bg-red-600/10 border-red-500/30"
                                    : "bg-amber-600/10 border-amber-500/30"
                            }`}>
                                {summary.dangerous > 0 ? (
                                    <Icons.Ban className="h-5 w-5 shrink-0 mt-0.5 text-red-400" />
                                ) : (
                                    <Icons.Warning className="h-5 w-5 shrink-0 mt-0.5 text-amber-400" />
                                )}
                                <div>
                                    <p className={`font-bold text-sm ${summary.dangerous > 0 ? "text-red-300" : "text-amber-300"}`}>
                                        {summary.dangerous > 0
                                            ? `${summary.dangerous} dangerous URL${summary.dangerous !== 1 ? "s" : ""} detected`
                                            : `${summary.suspicious} suspicious URL${summary.suspicious !== 1 ? "s" : ""} detected`}
                                    </p>
                                    <p className={`text-xs mt-1 opacity-75 ${summary.dangerous > 0 ? "text-red-300/80" : "text-amber-300/80"}`}>
                                        A 200 OK HTTP response does not mean a URL is safe. Phishing sites are intentionally live.
                                    </p>
                                </div>
                            </div>
                        )}

                        {results.skipped?.length > 0 && (
                            <div className="p-4 bg-amber-600/10 border border-amber-500/30 rounded-xl text-amber-300 text-sm flex items-center gap-3">
                                <Icons.Warning className="h-4 w-4 shrink-0" />
                                <span>
                                    <strong>{results.skipped.length} URL(s) skipped</strong> — invalid format or blocked.
                                </span>
                            </div>
                        )}

                        {/* AI Analysis */}
                        {summary.ai_analysis && (
                            <div className="rounded-xl border border-blue-500/30 bg-gradient-to-br from-blue-600/10 to-cyan-600/10 overflow-hidden">
                                <button
                                    onClick={() => setAiExpanded(!aiExpanded)}
                                    className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-all"
                                >
                                    <span className="flex items-center gap-2 text-sm font-bold text-blue-300">
                                        <Icons.Sparkle className="h-4 w-4" />
                                        AI Security Analysis
                                    </span>
                                    <Icons.ChevronDown className={`h-4 w-4 text-blue-400 transition-transform ${aiExpanded ? "rotate-180" : ""}`} />
                                </button>
                                {aiExpanded && (
                                    <div className="px-4 py-4 text-sm text-slate-300 whitespace-pre-wrap leading-relaxed border-t border-blue-500/30">
                                        {summary.ai_analysis}
                                    </div>
                                )}
                            </div>
                        )}

                        <div>
                            <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4">Results</h3>
                            <div className="space-y-3">
                                {[...results.results]
                                    .sort((a, b) => {
                                        const order = { dangerous: 0, suspicious: 1, safe: 2 };
                                        const ra = order[a.phishing?.risk_level ?? "safe"] ?? 2;
                                        const rb = order[b.phishing?.risk_level ?? "safe"] ?? 2;
                                        return ra - rb;
                                    })
                                    .map((result, i) => (
                                        <ResultCard key={i} result={result} />
                                    ))}
                            </div>
                        </div>
                    </div>
                )}
            </main>

            {!results && (
                <section id="about" className="border-t border-slate-700/30 py-12 px-4 bg-slate-900/30">
                    <div className="max-w-5xl mx-auto">
                        <h3 className="text-2xl font-bold text-slate-100 mb-8 text-center">Why Use TrvstPulse?</h3>
                        <div className="grid md:grid-cols-3 gap-6">
                            {[
                                { icon: Icons.Shield, title: "Phishing Detection", desc: "Heuristic analysis, Google Safe Browsing, and VirusTotal integration" },
                                { icon: Icons.Check, title: "Link Health", desc: "Verify if links are alive or broken with HTTP status tracking" },
                                { icon: Icons.Sparkle, title: "AI Analysis", desc: "Plain language security summaries powered by Gemini AI" },
                            ].map((feature, idx) => (
                                <div key={idx} className="glass-dark p-6 hover:border-slate-500/50 transition-all">
                                    <div className="w-10 h-10 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-lg flex items-center justify-center mb-4 border border-blue-500/30">
                                        <feature.icon className="h-5 w-5 text-blue-300" />
                                    </div>
                                    <h4 className="font-bold text-slate-100 mb-2">{feature.title}</h4>
                                    <p className="text-xs text-slate-400 leading-relaxed">{feature.desc}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                </section>
            )}

            {/* Footer */}
            <footer id="contact" className="border-t border-slate-700/30 bg-slate-900/50 py-8 px-4">
                <div className="max-w-5xl mx-auto text-center text-xs text-slate-400">
                    <p>© {new Date().getFullYear()} TrvstPulse. Advanced link security analysis.</p>
                </div>
            </footer>
        </div>
    );
}

export default LinkChecker;
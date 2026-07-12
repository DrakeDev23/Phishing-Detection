import { useState } from "react";
import { Icons } from "./Icons";
import About from "./About";
import Contact from "./Contact";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const MAX_URL_LENGTH = 2048;
const MAX_BULK_LENGTH = 50000;

function sanitizeUrl(raw) {
    let url = raw.trim();
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

function getRiskConfig(riskLevel) {
    switch (riskLevel) {
        case "dangerous":
            return {
                text: "text-red-400",
                border: "border-red-500/25",
                accent: "border-l-red-500",
                bg: "bg-red-500/10",
                badge: "bg-red-500/10 text-red-400 border border-red-500/25",
                label: "DANGEROUS",
                icon: <Icons.Ban className="h-4 w-4" />,
            };
        case "suspicious":
            return {
                text: "text-amber-400",
                border: "border-amber-500/25",
                accent: "border-l-amber-500",
                bg: "bg-amber-500/10",
                badge: "bg-amber-500/10 text-amber-400 border border-amber-500/25",
                label: "SUSPICIOUS",
                icon: <Icons.Warning className="h-4 w-4" />,
            };
        default:
            return {
                text: "text-emerald-400",
                border: "border-emerald-500/25",
                accent: "border-l-emerald-500",
                bg: "bg-emerald-500/10",
                badge: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25",
                label: "SAFE",
                icon: <Icons.Check className="h-4 w-4" />,
            };
    }
}

function RiskBadge({ riskLevel }) {
    const cfg = getRiskConfig(riskLevel);
    return (
        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-semibold tracking-wide ${cfg.badge}`}>
            {cfg.icon}
            {cfg.label}
        </span>
    );
}

function StatusBadge({ isAlive, statusCode }) {
    if (isAlive) {
        return (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-semibold text-[#6C93FF] bg-[#141B2E] border border-[#2B3B63]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#6C93FF] inline-block" />
                {statusCode} OK
            </span>
        );
    }
    return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-semibold text-[#8B93A7] bg-[#171C27] border border-[#262D3D]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#8B93A7] inline-block" />
            {statusCode || "No Response"}
        </span>
    );
}

function PhishingPanel({ phishing }) {
    const [expanded, setExpanded] = useState(false);
    if (!phishing) return null;

    const hasFlags = phishing.heuristic_flags?.length > 0;
    const hasGSB = phishing.safe_browsing_threat;
    const hasVT = phishing.virustotal_summary;

    return (
        <div className="mt-4 rounded-md border border-[#262D3D] overflow-hidden">
            <button
                onClick={() => setExpanded(!expanded)}
                className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors"
            >
                <div className="flex items-center gap-3">
                    <Icons.Shield className="h-4 w-4 text-[#8B93A7]" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-[#E7EAF0]">
                        Phishing Analysis
                    </span>
                    <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded-md bg-[#171C27] border border-[#262D3D] text-[#8B93A7]">
                        Score: {phishing.phishing_score ?? "—"}
                    </span>
                </div>
                <Icons.ChevronDown className={`h-4 w-4 text-[#8B93A7] transition-transform ${expanded ? "rotate-180" : ""}`} />
            </button>

            {expanded && (
                <div className="px-4 py-4 space-y-3 border-t border-[#262D3D]">
                    {hasGSB && (
                        <div className="flex items-start gap-3 p-3 rounded-md bg-red-500/10 border border-red-500/25">
                            <Icons.Ban className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                            <div>
                                <p className="text-xs font-semibold text-red-400">Google Safe Browsing</p>
                                <p className="text-xs text-red-400/80 mt-0.5">{phishing.safe_browsing_threat}</p>
                            </div>
                        </div>
                    )}

                    {hasVT && (
                        <div className={`flex items-start gap-3 p-3 rounded-md border ${phishing.virustotal_summary?.includes("malicious") || phishing.virustotal_summary?.includes("suspicious")
                            ? "bg-red-500/10 border-red-500/25"
                            : "bg-[#171C27] border-[#262D3D]"
                            }`}>
                            <Icons.Sparkle className="h-4 w-4 text-[#8B93A7] mt-0.5 shrink-0" />
                            <div>
                                <p className="text-xs font-semibold text-[#E7EAF0]">VirusTotal</p>
                                <p className="text-xs text-[#8B93A7] mt-0.5">{phishing.virustotal_summary}</p>
                            </div>
                        </div>
                    )}

                    {hasFlags ? (
                        <div>
                            <p className="text-xs font-semibold text-[#E7EAF0] mb-2">Heuristic Flags ({phishing.heuristic_flags.length})</p>
                            <ul className="space-y-2">
                                {phishing.heuristic_flags.map((flag, i) => (
                                    <li key={i} className="text-xs px-3 py-2 rounded-md flex items-start gap-2 bg-[#171C27] text-[#8B93A7] border border-[#262D3D]">
                                        <span className="text-[#6C93FF] mt-0.5 shrink-0">–</span>
                                        <span>{flag}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ) : (
                        <p className="text-xs text-[#8B93A7] italic">No heuristic flags triggered.</p>
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
        <div className={`rounded-md border border-[#262D3D] border-l-4 ${cfg.accent} bg-[#171C27] p-4 hover:border-[#2B3B63] transition-colors`}>
            <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-[#E7EAF0] truncate font-medium">{result.url}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                    {result.response_time_ms != null && (
                        <span className="text-xs font-mono text-[#8B93A7]">{result.response_time_ms}ms</span>
                    )}
                    <StatusBadge isAlive={result.is_alive} statusCode={result.status_code} />
                </div>
            </div>

            {result.redirect_url && (
                <p className="text-xs text-[#8B93A7] mb-2 flex items-center gap-1">
                    <Icons.Arrow className="h-3 w-3 shrink-0" />
                    Redirected to: <span className="font-mono truncate text-[#E7EAF0]">{result.redirect_url}</span>
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
                <div className="mt-4 p-3 rounded-md bg-[#141B2E] border border-[#2B3B63] text-xs text-[#E7EAF0] whitespace-pre-wrap leading-relaxed">
                    <p className="font-semibold mb-2 flex items-center gap-1.5 text-[#6C93FF]">
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
        <div className="min-h-[calc(100vh-4rem)] flex flex-col bg-[#10141C]">
            <main id="home" className="max-w-5xl mx-auto px-4 py-16 w-full flex-1">
                <div className="text-center mb-12">
                    <p className="text-xs font-mono uppercase tracking-widest text-[#6C93FF] mb-3">Link Security Report</p>
                    <h2 className="text-5xl md:text-6xl font-serif font-bold text-[#E7EAF0] mb-4">
                        TrvstPulse
                    </h2>
                    <p className="text-base text-[#8B93A7] max-w-md mx-auto">
                        Verify a link before you trust it.
                    </p>
                </div>

                <div className="flex justify-center border-b border-[#262D3D] mb-8">
                    {["manual", "bulk"].map((mode) => (
                        <button
                            key={mode}
                            onClick={() => setInputMode(mode)}
                            className={`px-6 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${inputMode === mode
                                ? "border-[#6C93FF] text-[#E7EAF0]"
                                : "border-transparent text-[#8B93A7] hover:text-[#E7EAF0]"
                                }`}
                        >
                            {mode === "manual" ? "Manual URLs" : "Bulk / Paste Text"}
                        </button>
                    ))}
                </div>

                <div className="border border-[#262D3D] bg-[#171C27] rounded-md p-8 mb-8">
                    <label className="block text-sm font-semibold text-[#E7EAF0] mb-4">
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
                                            className="flex-1 px-4 py-3 rounded-md bg-[#10141C] border border-[#262D3D] text-sm font-mono text-[#E7EAF0] placeholder:text-[#8B93A7]/60 focus:outline-none focus:border-[#6C93FF] focus:ring-1 focus:ring-[#6C93FF] transition-colors"
                                            onKeyDown={(e) => e.key === "Enter" && addUrl()}
                                        />
                                        {urls.length > 1 && (
                                            <button
                                                onClick={() => removeUrl(i)}
                                                aria-label="Remove URL"
                                                className="px-3 py-3 rounded-md text-[#8B93A7] hover:text-red-400 hover:bg-red-500/10 transition-colors"
                                            >
                                                <Icons.Close className="h-4 w-4" />
                                            </button>
                                        )}
                                    </div>
                                ))}
                            </div>
                            <button
                                onClick={addUrl}
                                disabled={urls.length >= 20}
                                className="text-[#6C93FF] hover:text-[#8FB0FF] text-sm font-medium transition-colors disabled:opacity-40"
                            >
                                + Add URL
                            </button>
                        </div>
                    ) : (
                        <div>
                            <p className="text-xs font-mono text-[#8B93A7] mb-3">
                                {bulkText.length}/{MAX_BULK_LENGTH} characters
                            </p>
                            <textarea
                                value={bulkText}
                                onChange={handleBulkTextChange}
                                maxLength={MAX_BULK_LENGTH}
                                placeholder="Paste HTML, markdown, emails, or any text containing URLs..."
                                className="w-full h-48 resize-none px-4 py-3 rounded-md bg-[#10141C] border border-[#262D3D] text-sm font-mono text-[#E7EAF0] placeholder:text-[#8B93A7]/60 focus:outline-none focus:border-[#6C93FF] focus:ring-1 focus:ring-[#6C93FF] transition-colors"
                            />
                        </div>
                    )}

                    {error && (
                        <div className="mt-4 p-4 bg-red-500/10 border border-red-500/25 rounded-md text-red-400 text-sm flex items-center gap-3">
                            <Icons.Warning className="h-4 w-4 shrink-0" />
                            {error}
                        </div>
                    )}

                    <div className="flex gap-3 mt-6">
                        <button
                            onClick={inputMode === "manual" ? handleManualCheck : handleExtractAndCheck}
                            disabled={loading}
                            className="flex-1 flex items-center justify-center gap-2 px-6 py-3 rounded-md bg-[#3D63DD] text-white text-sm font-semibold hover:bg-[#4E76F2] disabled:opacity-60 transition-colors"
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
                            <button
                                onClick={handleReset}
                                className="px-6 py-3 rounded-md border border-[#262D3D] text-[#E7EAF0] text-sm font-semibold hover:bg-white/5 transition-colors"
                            >
                                Reset
                            </button>
                        )}
                    </div>
                </div>

                {results && (
                    <div className="space-y-6">
                        <div className="grid grid-cols-2 sm:grid-cols-5 gap-px bg-[#262D3D] border border-[#262D3D]">
                            {[
                                { label: "Total", value: summary.total },
                                { label: "Alive", value: summary.alive },
                                { label: "Broken", value: summary.dead },
                                { label: "Suspicious", value: summary.suspicious ?? 0 },
                                { label: "Dangerous", value: summary.dangerous ?? 0 },
                            ].map((stat, idx) => (
                                <div key={idx} className="bg-[#171C27] p-4 text-center">
                                    <p className="text-3xl font-serif font-bold text-[#E7EAF0]">{stat.value}</p>
                                    <p className="text-xs text-[#8B93A7] font-mono mt-2 uppercase tracking-wider">{stat.label}</p>
                                </div>
                            ))}
                        </div>

                        {(summary.dangerous > 0 || summary.suspicious > 0) && (
                            <div className={`p-4 rounded-md border flex items-start gap-3 ${summary.dangerous > 0
                                ? "bg-red-500/10 border-red-500/25"
                                : "bg-amber-500/10 border-amber-500/25"
                                }`}>
                                {summary.dangerous > 0 ? (
                                    <Icons.Ban className="h-5 w-5 shrink-0 mt-0.5 text-red-400" />
                                ) : (
                                    <Icons.Warning className="h-5 w-5 shrink-0 mt-0.5 text-amber-400" />
                                )}
                                <div>
                                    <p className={`font-semibold text-sm ${summary.dangerous > 0 ? "text-red-400" : "text-amber-400"}`}>
                                        {summary.dangerous > 0
                                            ? `${summary.dangerous} dangerous URL${summary.dangerous !== 1 ? "s" : ""} detected`
                                            : `${summary.suspicious} suspicious URL${summary.suspicious !== 1 ? "s" : ""} detected`}
                                    </p>
                                    <p className={`text-xs mt-1 ${summary.dangerous > 0 ? "text-red-400/80" : "text-amber-400/80"}`}>
                                        A 200 OK HTTP response does not mean a URL is safe. Phishing sites are intentionally live.
                                    </p>
                                </div>
                            </div>
                        )}

                        {results.skipped?.length > 0 && (
                            <div className="p-4 bg-amber-500/10 border border-amber-500/25 rounded-md text-amber-400 text-sm flex items-center gap-3">
                                <Icons.Warning className="h-4 w-4 shrink-0" />
                                <span>
                                    <strong>{results.skipped.length} URL(s) skipped</strong> — invalid format or blocked.
                                </span>
                            </div>
                        )}

                        {summary.ai_analysis && (
                            <div className="rounded-md border border-[#2B3B63] bg-[#141B2E] overflow-hidden">
                                <button
                                    onClick={() => setAiExpanded(!aiExpanded)}
                                    className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors"
                                >
                                    <span className="flex items-center gap-2 text-sm font-semibold text-[#6C93FF]">
                                        <Icons.Sparkle className="h-4 w-4" />
                                        AI Security Analysis
                                    </span>
                                    <Icons.ChevronDown className={`h-4 w-4 text-[#6C93FF] transition-transform ${aiExpanded ? "rotate-180" : ""}`} />
                                </button>
                                {aiExpanded && (
                                    <div className="px-4 py-4 text-sm text-[#E7EAF0] whitespace-pre-wrap leading-relaxed border-t border-[#2B3B63]">
                                        {summary.ai_analysis}
                                    </div>
                                )}
                            </div>
                        )}

                        <div>
                            <h3 className="text-xs font-mono font-semibold text-[#8B93A7] uppercase tracking-wider mb-4">Results</h3>
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

            {!results && <About />}

            <Contact />
        </div>
    );
}

export default LinkChecker;
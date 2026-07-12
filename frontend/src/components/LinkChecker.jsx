import { useState } from "react";
import {
    ArrowRight,
    Ban,
    ChevronDown,
    CircleCheck,
    CircleX,
    Clipboard,
    HeartPulse,
    Link,
    Link2Off,
    ListChecks,
    LoaderCircle,
    Search,
    ShieldCheck,
    ShieldAlert,
    ShieldQuestionMark,
    Sparkles,
    SquarePen,
    TriangleAlert,
} from "lucide-react";
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
                icon: <Ban className="h-4 w-4" />,
            };
        case "suspicious":
            return {
                text: "text-amber-400",
                border: "border-amber-500/25",
                accent: "border-l-amber-500",
                bg: "bg-amber-500/10",
                badge: "bg-amber-500/10 text-amber-400 border border-amber-500/25",
                label: "SUSPICIOUS",
                icon: <TriangleAlert className="h-4 w-4" />,
            };
        default:
            return {
                text: "text-emerald-400",
                border: "border-emerald-500/25",
                accent: "border-l-emerald-500",
                bg: "bg-emerald-500/10",
                badge: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25",
                label: "SAFE",
                icon: <CircleCheck className="h-4 w-4" />,
            };
    }
}

function RiskBadge({ riskLevel }) {
    const cfg = getRiskConfig(riskLevel);
    return (
        <span className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-mono font-bold text-sm tracking-wider shadow-lg ${cfg.badge}`}>
            {cfg.icon}
            {cfg.label}
        </span>
    );
}

function StatusBadge({ isAlive, statusCode }) {
    if (isAlive) {
        return (
            <span className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono font-semibold text-emerald-300 bg-emerald-950/40 border border-emerald-500/50 shadow-sm">
                <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-pulse" />
                {statusCode} OK
            </span>
        );
    }
    return (
        <span className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono font-semibold text-red-300 bg-red-950/40 border border-red-500/50 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-red-400 inline-block" />
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
                    <ShieldCheck className="h-4 w-4 text-[#8B93A7]" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-[#E7EAF0]">
                        Phishing Analysis
                    </span>
                    <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded-md bg-[#171C27] border border-[#262D3D] text-[#8B93A7]">
                        Score: {phishing.phishing_score ?? "—"}
                    </span>
                </div>
                <ChevronDown className={`h-4 w-4 text-[#8B93A7] transition-transform ${expanded ? "rotate-180" : ""}`} />
            </button>

            {expanded && (
                <div className="px-4 py-4 space-y-3 border-t border-[#262D3D]">
                    {hasGSB && (
                        <div className="flex items-start gap-3 p-3 rounded-md bg-red-500/10 border border-red-500/25">
                            <Ban className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
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
                            <Sparkles className="h-4 w-4 text-[#8B93A7] mt-0.5 shrink-0" />
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
        <div className={`rounded-xl border-2 border-l-4 ${cfg.border} ${cfg.accent} bg-gradient-to-br from-slate-900/60 to-slate-800/40 p-5 hover:shadow-xl transition-all shadow-md backdrop-blur-sm`}>
            <div className="flex items-start justify-between gap-3 mb-4">
                <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-slate-100 truncate font-semibold break-all">{result.url}</p>
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
                    <ArrowRight className="h-3 w-3 shrink-0" />
                    Redirected to: <span className="font-mono truncate text-[#E7EAF0]">{result.redirect_url}</span>
                </p>
            )}

            {result.error && (
                <p className="text-xs text-red-400 mb-2 flex items-center gap-1">
                    <TriangleAlert className="h-3 w-3 shrink-0" />
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
                        <Sparkles className="h-3.5 w-3.5" />
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
        <div className="min-h-[calc(100vh-4rem)] flex flex-col bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950">
            <main id="home" className="max-w-5xl mx-auto px-4 py-20 w-full flex-1">
                <div className="text-center mb-16">
                    <div className="flex items-center justify-center gap-2 mb-4">
                        <div className="h-px w-8 bg-gradient-to-r from-transparent to-cyan-500"></div>
                        <p className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-bold flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> Advanced Security Scanner</p>
                        <div className="h-px w-8 bg-gradient-to-l from-transparent to-cyan-500"></div>
                    </div>
                    <h2 className="text-6xl md:text-7xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 via-blue-300 to-cyan-300 mb-4 tracking-tight">
                        TrvstPulse
                    </h2>
                    <p className="text-lg text-slate-300 max-w-2xl mx-auto font-medium">
                        Verify every link before you trust it. Detect phishing, malware, and suspicious URLs instantly with advanced AI analysis.
                    </p>
                </div>

                <div className="flex justify-center gap-4 mb-8">
                    {["manual", "bulk"].map((mode) => (
                        <button
                            key={mode}
                            onClick={() => setInputMode(mode)}
                            className={`px-6 py-3 text-sm font-semibold rounded-lg transition-all duration-200 flex items-center gap-2 ${
                                inputMode === mode
                                    ? "bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/20"
                                    : "text-slate-300 hover:text-white hover:bg-slate-800/50 border border-slate-700"
                            }`}
                        >
                            {mode === "manual" ? (
                                <>
                                    <SquarePen className="h-4 w-4" /> Manual URLs
                                </>
                            ) : (
                                <>
                                    <Clipboard className="h-4 w-4" /> Bulk / Paste Text
                                </>
                            )}
                        </button>
                    ))}
                </div>

                <div className="border border-slate-700/50 bg-gradient-to-br from-slate-900/80 to-slate-900/50 backdrop-blur-sm rounded-xl p-8 mb-8 shadow-xl">
                    <label className="block text-sm font-bold text-slate-200 mb-4 uppercase tracking-wide">
                        {inputMode === "manual" ? (
                            <span className="flex items-center gap-2"><Link className="h-4 w-4" /> Enter URLs (max 20)</span>
                        ) : (
                            <span className="flex items-center gap-2"><Clipboard className="h-4 w-4" /> Paste any text</span>
                        )}
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
                                            className="flex-1 px-4 py-3 rounded-lg bg-slate-800/50 border border-slate-600/50 text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all shadow-sm"
                                            onKeyDown={(e) => e.key === "Enter" && addUrl()}
                                        />
                                        {urls.length > 1 && (
                                            <button
                                                onClick={() => removeUrl(i)}
                                                aria-label="Remove URL"
                                                className="px-3 py-3 rounded-md text-[#8B93A7] hover:text-red-400 hover:bg-red-500/10 transition-colors"
                                            >
                                                <CircleX className="h-4 w-4" />
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
                                className="w-full h-48 resize-none px-4 py-3 rounded-lg bg-slate-800/50 border border-slate-600/50 text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all shadow-sm"
                            />
                        </div>
                    )}

                    {error && (
                        <div className="mt-4 p-4 bg-red-500/10 border border-red-500/25 rounded-md text-red-400 text-sm flex items-center gap-3">
                            <TriangleAlert className="h-4 w-4 shrink-0" />
                            {error}
                        </div>
                    )}

                    <div className="flex gap-3 mt-8">
                        <button
                            onClick={inputMode === "manual" ? handleManualCheck : handleExtractAndCheck}
                            disabled={loading}
                            className="flex-1 flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-sm font-bold hover:from-cyan-600 hover:to-blue-700 disabled:opacity-50 transition-all shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 disabled:shadow-none uppercase tracking-wide"
                        >
                            {loading ? (
                                <>
                                    <LoaderCircle className="h-5 w-5 animate-spin" />
                                    Scanning...
                                </>
                            ) : (
                                <>
                                    <ShieldCheck className="h-5 w-5" />
                                    Scan Now
                                </>
                            )}
                        </button>
                        {results && (
                            <button
                                onClick={handleReset}
                                className="px-6 py-3 rounded-lg border-2 border-slate-600 text-slate-200 text-sm font-semibold hover:bg-slate-800/50 hover:border-slate-500 transition-all"
                            >
                                Reset
                            </button>
                        )}
                    </div>
                </div>

                {results && (
                    <div className="space-y-6">
                        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                            {[
                                { label: "Total", value: summary.total, icon: <ListChecks className="h-6 w-6" /> },
                                { label: "Alive", value: summary.alive, icon: <HeartPulse className="h-6 w-6" /> },
                                { label: "Broken", value: summary.dead, icon: <Link2Off className="h-6 w-6" /> },
                                { label: "Suspicious", value: summary.suspicious ?? 0, icon: <ShieldQuestionMark className="h-6 w-6" /> },
                                { label: "Dangerous", value: summary.dangerous ?? 0, icon: <ShieldAlert className="h-6 w-6" /> },
                            ].map((stat, idx) => (
                                <div key={idx} className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 p-6 rounded-lg text-center hover:border-slate-600/80 transition-all shadow-md">
                                    <div className="flex justify-center mb-2">{stat.icon}</div>
                                    <p className="text-4xl font-bold text-cyan-300 mb-2">{stat.value}</p>
                                    <p className="text-xs text-slate-400 font-mono uppercase tracking-widest font-semibold">{stat.label}</p>
                                </div>
                            ))}
                        </div>

                        {(summary.dangerous > 0 || summary.suspicious > 0) && (
                            <div className={`p-4 rounded-md border flex items-start gap-3 ${summary.dangerous > 0
                                ? "bg-red-500/10 border-red-500/25"
                                : "bg-amber-500/10 border-amber-500/25"
                                }`}>
                                {summary.dangerous > 0 ? (
                                    <Ban className="h-5 w-5 shrink-0 mt-0.5 text-red-400" />
                                ) : (
                                    <TriangleAlert className="h-5 w-5 shrink-0 mt-0.5 text-amber-400" />
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
                                <TriangleAlert className="h-4 w-4 shrink-0" />
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
                                        <Sparkles className="h-4 w-4" />
                                        AI Security Analysis
                                    </span>
                                    <ChevronDown className={`h-4 w-4 text-[#6C93FF] transition-transform ${aiExpanded ? "rotate-180" : ""}`} />
                                </button>
                                {aiExpanded && (
                                    <div className="px-4 py-4 text-sm text-[#E7EAF0] whitespace-pre-wrap leading-relaxed border-t border-[#2B3B63]">
                                        {summary.ai_analysis}
                                    </div>
                                )}
                            </div>
                        )}

                        <div>
                            <h3 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                                <Search className="h-5 w-5" /> Scan Results
                            </h3>
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

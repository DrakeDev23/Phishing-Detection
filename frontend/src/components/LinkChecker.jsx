import { useState } from "react";

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


function IconShield({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
    );
}

function IconWarning({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        </svg>
    );
}

function IconBan({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
    );
}

function IconCheck({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
    );
}

function IconArrowRight({ className = "h-3 w-3" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
    );
}

function IconChevronDown({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
    );
}

function IconFlag({ className = "h-3 w-3" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 21V4m0 0l9-1 9 1v13l-9-1-9 1V4z" />
        </svg>
    );
}

function IconBeaker({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v8.5L5.5 17A2 2 0 007.32 20h9.36a2 2 0 001.82-3L15 11.5V3M9 3h6M9 3H7m8 0h2" />
        </svg>
    );
}

function IconBell({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
    );
}

function IconSparkle({ className = "h-4 w-4" }) {
    return (
        <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
        </svg>
    );
}

function IconSpinner({ className = "h-4 w-4" }) {
    return (
        <svg className={`animate-spin ${className}`} fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
    );
}


function getRiskConfig(riskLevel) {
    switch (riskLevel) {
        case "dangerous":
            return {
                cardBorder: "border-red-400",
                cardBg: "bg-red-50",
                badge: "bg-red-100 text-red-700 border border-red-300",
                headerBg: "bg-red-100",
                panelBorder: "border-red-300",
                label: "DANGEROUS",
                icon: <IconBan className="h-3.5 w-3.5" />,
                flagBg: "bg-red-100 text-red-700",
                scoreBg: "bg-red-200 text-red-800",
            };
        case "suspicious":
            return {
                cardBorder: "border-yellow-400",
                cardBg: "bg-yellow-50",
                badge: "bg-yellow-100 text-yellow-800 border border-yellow-300",
                headerBg: "bg-yellow-100",
                panelBorder: "border-yellow-300",
                label: "SUSPICIOUS",
                icon: <IconWarning className="h-3.5 w-3.5" />,
                flagBg: "bg-yellow-100 text-yellow-800",
                scoreBg: "bg-yellow-200 text-yellow-900",
            };
        default:
            return {
                cardBorder: "border-green-200",
                cardBg: "bg-green-50",
                badge: "bg-green-100 text-green-700 border border-green-200",
                headerBg: "bg-green-100",
                panelBorder: "border-green-200",
                label: "SAFE",
                icon: <IconCheck className="h-3.5 w-3.5" />,
                flagBg: "bg-green-100 text-green-700",
                scoreBg: "bg-green-200 text-green-800",
            };
    }
}


function StatusBadge({ isAlive, statusCode }) {
    if (isAlive) {
        return (
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold bg-blue-100 text-blue-700">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 inline-block" />
                {statusCode} OK
            </span>
        );
    }
    return (
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-600">
            <span className="w-1.5 h-1.5 rounded-full bg-gray-400 inline-block" />
            {statusCode || "No Response"}
        </span>
    );
}

function RiskBadge({ riskLevel }) {
    const cfg = getRiskConfig(riskLevel);
    return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold ${cfg.badge}`}>
            {cfg.icon}
            {cfg.label}
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
        <div className={`mt-3 rounded-lg border ${cfg.panelBorder} overflow-hidden`}>
            <button
                onClick={() => setExpanded(!expanded)}
                className={`w-full flex items-center justify-between px-3 py-2 ${cfg.headerBg} hover:brightness-95 transition-all`}
            >
                <div className="flex items-center gap-2">
                    <IconShield className="h-3.5 w-3.5 text-gray-600" />
                    <span className="text-xs font-bold uppercase tracking-wide text-gray-700">
                        Phishing Analysis
                    </span>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${cfg.scoreBg}`}>
                        Score: {phishing.phishing_score ?? "—"}
                    </span>
                    {hasFlags && (
                        <span className="text-xs text-gray-500">
                            {phishing.heuristic_flags.length} flag{phishing.heuristic_flags.length !== 1 ? "s" : ""}
                        </span>
                    )}
                </div>
                <IconChevronDown className={`h-4 w-4 text-gray-500 transition-transform ${expanded ? "rotate-180" : ""}`} />
            </button>

            {expanded && (
                <div className="px-3 py-3 space-y-2 bg-white">

                    {hasGSB && (
                        <div className="flex items-start gap-2 p-2 rounded bg-red-50 border border-red-200">
                            <IconBell className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
                            <div>
                                <p className="text-xs font-bold text-red-700">Google Safe Browsing</p>
                                <p className="text-xs text-red-600">{phishing.safe_browsing_threat}</p>
                            </div>
                        </div>
                    )}

                    {hasVT && (
                        <div className={`flex items-start gap-2 p-2 rounded border ${phishing.virustotal_summary?.includes("malicious") || phishing.virustotal_summary?.includes("suspicious")
                            ? "bg-red-50 border-red-200"
                            : "bg-gray-50 border-gray-200"
                            }`}>
                            <IconBeaker className="h-4 w-4 text-gray-500 mt-0.5 shrink-0" />
                            <div>
                                <p className="text-xs font-bold text-gray-700">VirusTotal</p>
                                <p className="text-xs text-gray-600">{phishing.virustotal_summary}</p>
                            </div>
                        </div>
                    )}

                    {hasFlags ? (
                        <div>
                            <p className="text-xs font-bold text-gray-600 mb-1.5">Heuristic Flags</p>
                            <ul className="space-y-1">
                                {phishing.heuristic_flags.map((flag, i) => (
                                    <li key={i} className={`text-xs px-2 py-1.5 rounded flex items-start gap-1.5 ${cfg.flagBg}`}>
                                        <IconFlag className="h-3 w-3 mt-0.5 shrink-0" />
                                        {flag}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ) : (
                        <p className="text-xs text-gray-400 italic">No heuristic flags triggered.</p>
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
        <div className={`rounded-xl border-2 p-4 shadow-sm ${cfg.cardBorder} ${cfg.cardBg}`}>
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-gray-800 truncate font-medium">{result.url}</p>

                    {result.redirect_url && (
                        <p className="text-xs text-gray-500 mt-1 flex items-center gap-1">
                            <IconArrowRight className="h-3 w-3 shrink-0" />
                            Redirected to:{" "}
                            <span className="font-mono truncate">{result.redirect_url}</span>
                        </p>
                    )}

                    {result.error && (
                        <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                            <IconWarning className="h-3 w-3 shrink-0" />
                            {result.error}
                        </p>
                    )}
                </div>

                <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                    {result.response_time_ms != null && (
                        <span className="text-xs text-gray-400">{result.response_time_ms}ms</span>
                    )}
                    <StatusBadge isAlive={result.is_alive} statusCode={result.status_code} />
                    {result.phishing && <RiskBadge riskLevel={result.phishing.risk_level} />}
                </div>
            </div>

            <PhishingPanel phishing={result.phishing} />

            {result.ai_analysis && (
                <div className="mt-3 p-3 rounded-lg bg-blue-50 border border-blue-200 text-xs text-blue-800 whitespace-pre-wrap">
                    <p className="font-bold mb-1 flex items-center gap-1.5">
                        <IconSparkle className="h-3.5 w-3.5" />
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
        <div className="min-h-screen bg-white flex flex-col">
            <main className="max-w-4xl mx-auto px-4 py-10 w-full">
                <div className="text-center mb-10">
                    <h2 className="text-4xl font-serif font-bold text-gray-800 mb-3">TrvstPulse</h2>
                    <p className="text-gray-500 text-lg">Check if your links are alive and safe</p>
                </div>

                <div className="flex gap-2 mb-6 bg-gray-100 p-1 rounded-xl w-fit mx-auto">
                    <button
                        onClick={() => setInputMode("manual")}
                        className={`px-5 py-2 rounded-lg text-sm font-semibold transition-all ${inputMode === "manual" ? "bg-blue-500 text-white shadow" : "text-gray-600 hover:text-gray-800"}`}
                    >
                        Manual URLs
                    </button>
                    <button
                        onClick={() => setInputMode("bulk")}
                        className={`px-5 py-2 rounded-lg text-sm font-semibold transition-all ${inputMode === "bulk" ? "bg-blue-500 text-white shadow" : "text-gray-600 hover:text-gray-800"}`}
                    >
                        Bulk / Paste Text
                    </button>
                </div>

                <div className="bg-white rounded-2xl shadow-md border border-gray-200 p-6 mb-8">
                    {inputMode === "manual" ? (
                        <div>
                            <label className="block text-sm font-semibold text-gray-700 mb-3">
                                Enter URLs (max 20)
                            </label>
                            <div className="space-y-3">
                                {urls.map((url, i) => (
                                    <div key={i} className="flex gap-2">
                                        <input
                                            type="url"
                                            value={url}
                                            onChange={(e) => updateUrl(i, e.target.value)}
                                            placeholder="https://example.com"
                                            maxLength={MAX_URL_LENGTH}
                                            className="flex-1 border border-gray-300 rounded-lg px-4 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
                                            onKeyDown={(e) => e.key === "Enter" && addUrl()}
                                        />
                                        {urls.length > 1 && (
                                            <button
                                                onClick={() => removeUrl(i)}
                                                className="text-gray-400 hover:text-red-500 px-2 transition-colors text-lg leading-none"
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
                                className="mt-3 text-blue-500 hover:text-blue-700 text-sm font-medium disabled:opacity-40"
                            >
                                + Add another URL
                            </button>
                        </div>
                    ) : (
                        <div>
                            <label className="block text-sm font-semibold text-gray-700 mb-1">
                                Paste any text — URLs will be extracted automatically
                            </label>
                            <p className="text-xs text-gray-400 mb-3">
                                {bulkText.length}/{MAX_BULK_LENGTH} characters
                            </p>
                            <textarea
                                value={bulkText}
                                onChange={handleBulkTextChange}
                                maxLength={MAX_BULK_LENGTH}
                                placeholder="Paste HTML, markdown, emails, or any text containing URLs..."
                                className="w-full border border-gray-300 rounded-lg px-4 py-3 text-sm font-mono h-40 resize-none focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
                            />
                        </div>
                    )}

                    {error && (
                        <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm flex items-center gap-2">
                            <IconWarning className="h-4 w-4 shrink-0" />
                            {error}
                        </div>
                    )}

                    <div className="flex gap-3 mt-5">
                        <button
                            onClick={inputMode === "manual" ? handleManualCheck : handleExtractAndCheck}
                            disabled={loading}
                            className="flex-1 bg-blue-500 hover:bg-blue-600 disabled:bg-blue-300 text-white font-semibold py-3 rounded-xl transition-colors flex items-center justify-center gap-2"
                        >
                            {loading ? (
                                <>
                                    <IconSpinner className="h-4 w-4" />
                                    Checking links...
                                </>
                            ) : (
                                <>
                                    <IconCheck className="h-4 w-4" />
                                    Check Links
                                </>
                            )}
                        </button>
                        {results && (
                            <button
                                onClick={handleReset}
                                className="px-5 py-3 border border-gray-300 text-gray-600 font-semibold rounded-xl hover:bg-gray-50 transition-colors"
                            >
                                Reset
                            </button>
                        )}
                    </div>
                </div>

                {results && (
                    <div>
                        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
                            <div className="bg-white border border-gray-200 rounded-xl p-4 text-center shadow-sm">
                                <p className="text-3xl font-bold text-gray-800">{summary.total}</p>
                                <p className="text-xs text-gray-500 font-medium mt-1">Total</p>
                            </div>
                            <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center shadow-sm">
                                <p className="text-3xl font-bold text-green-600">{summary.alive}</p>
                                <p className="text-xs text-green-600 font-medium mt-1">Alive</p>
                            </div>
                            <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 text-center shadow-sm">
                                <p className="text-3xl font-bold text-gray-500">{summary.dead}</p>
                                <p className="text-xs text-gray-500 font-medium mt-1">Broken</p>
                            </div>
                            <div className="bg-yellow-50 border border-yellow-300 rounded-xl p-4 text-center shadow-sm">
                                <p className="text-3xl font-bold text-yellow-600">{summary.suspicious ?? 0}</p>
                                <p className="text-xs text-yellow-700 font-medium mt-1">Suspicious</p>
                            </div>
                            <div className="bg-red-50 border border-red-300 rounded-xl p-4 text-center shadow-sm">
                                <p className="text-3xl font-bold text-red-600">{summary.dangerous ?? 0}</p>
                                <p className="text-xs text-red-600 font-medium mt-1">Dangerous</p>
                            </div>
                        </div>

                        {(summary.dangerous > 0 || summary.suspicious > 0) && (
                            <div className={`mb-5 p-4 rounded-xl border flex items-start gap-3 ${summary.dangerous > 0
                                ? "bg-red-50 border-red-300 text-red-800"
                                : "bg-yellow-50 border-yellow-300 text-yellow-800"
                                }`}>
                                {summary.dangerous > 0
                                    ? <IconBan className="h-5 w-5 shrink-0 mt-0.5" />
                                    : <IconWarning className="h-5 w-5 shrink-0 mt-0.5" />
                                }
                                <div>
                                    <p className="font-bold text-sm">
                                        {summary.dangerous > 0
                                            ? `${summary.dangerous} dangerous URL${summary.dangerous !== 1 ? "s" : ""} detected — do not visit.`
                                            : `${summary.suspicious} suspicious URL${summary.suspicious !== 1 ? "s" : ""} detected — proceed with caution.`}
                                    </p>
                                    <p className="text-xs mt-0.5 opacity-75">
                                        A 200 OK HTTP response does not mean a URL is safe.
                                        Phishing sites are intentionally live and return 200.
                                    </p>
                                </div>
                            </div>
                        )}

                        {results.skipped?.length > 0 && (
                            <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-xl text-yellow-700 text-sm flex items-center gap-2">
                                <IconWarning className="h-4 w-4 shrink-0" />
                                <span>
                                    <strong>{results.skipped.length} URL(s) skipped</strong> — invalid format or blocked by security policy.
                                </span>
                            </div>
                        )}

                        {summary.ai_analysis && (
                            <div className="mb-5 rounded-xl border border-blue-200 overflow-hidden">
                                <button
                                    onClick={() => setAiExpanded(!aiExpanded)}
                                    className="w-full flex items-center justify-between px-4 py-3 bg-blue-50 hover:bg-blue-100 transition-colors"
                                >
                                    <span className="flex items-center gap-2 text-sm font-bold text-blue-800">
                                        <IconSparkle className="h-4 w-4" />
                                        AI Security Analysis (Gemini)
                                    </span>
                                    <IconChevronDown className={`h-4 w-4 text-blue-500 transition-transform ${aiExpanded ? "rotate-180" : ""}`} />
                                </button>
                                {aiExpanded && (
                                    <div className="px-4 py-3 bg-white text-sm text-gray-700 whitespace-pre-wrap leading-relaxed">
                                        {summary.ai_analysis}
                                    </div>
                                )}
                            </div>
                        )}

                        <div className="space-y-3">
                            <h3 className="font-semibold text-gray-700 text-sm uppercase tracking-wide">
                                Individual Results
                            </h3>
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
                )}
            </main>

            <section id="about" className="max-w-4xl mx-auto px-4 py-12 border-t border-gray-200 mt-4">
                <h3 className="text-2xl font-serif font-bold text-gray-800 mb-4">About TrvstPulse</h3>
                <div className="grid sm:grid-cols-3 gap-6 text-sm text-gray-600">
                    <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
                        <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center mb-3">
                            <IconShield className="h-4 w-4 text-blue-600" />
                        </div>
                        <h4 className="font-bold text-gray-800 mb-1">Phishing Detection</h4>
                        <p className="leading-relaxed">Combines heuristic analysis, Google Safe Browsing, and VirusTotal to flag malicious or suspicious URLs before you click.</p>
                    </div>
                    <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
                        <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center mb-3">
                            <IconCheck className="h-4 w-4 text-green-600" />
                        </div>
                        <h4 className="font-bold text-gray-800 mb-1">Link Health Checks</h4>
                        <p className="leading-relaxed">Verifies whether links are alive or broken, tracks redirects, and reports HTTP status codes  useful for auditing newsletters and docs.</p>
                    </div>
                    <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
                        <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center mb-3">
                            <IconSparkle className="h-4 w-4 text-purple-600" />
                        </div>
                        <h4 className="font-bold text-gray-800 mb-1">AI Analysis</h4>
                        <p className="leading-relaxed">An AI layer summarizes risk across all scanned URLs, giving you a plain language security overview alongside the raw results.</p>
                    </div>
                </div>
            </section>

            <footer id="contact" className="border-t border-gray-200 bg-gray-50 mt-4">
                <div className="max-w-4xl mx-auto px-4 py-8">
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
                        <div>
                            <p className="font-serif font-bold text-gray-800 text-lg">TrvstPulse</p>
                            <p className="text-xs text-gray-400 mt-1">Link safety & phishing detection tool</p>
                        </div>
                        <div className="flex flex-col gap-2 text-sm text-gray-600">
                            <p className="font-semibold text-gray-700 text-xs uppercase tracking-wide mb-1">Contact & Social</p>
                            <a
                                className="hover:text-blue-600 transition-colors flex items-center gap-2"
                            >
                                <span className="w-7 h-7 rounded-full bg-blue-100 flex items-center justify-center shrink-0">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                    </svg>
                                </span>
                                maccogoth@gmail.com
                            </a>
                            <a
                                href="https://www.facebook.com/stephen.mart.98"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="hover:text-blue-600 transition-colors flex items-center gap-2"
                            >
                                <span className="w-7 h-7 rounded-full bg-blue-100 flex items-center justify-center shrink-0">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 text-blue-600" fill="currentColor" viewBox="0 0 24 24">
                                        <path d="M24 12.073C24 5.405 18.627 0 12 0S0 5.405 0 12.073C0 18.1 4.388 23.094 10.125 24v-8.437H7.078v-3.49h3.047V9.413c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.49h-2.796V24C19.612 23.094 24 18.1 24 12.073z" />
                                    </svg>
                                </span>
                                facebook.com
                            </a>
                        </div>
                    </div>
                    <p className="text-xs text-gray-400 mt-6 text-center">
                        © {new Date().getFullYear()} TrvstPulse. Built for link safety awareness.
                    </p>
                </div>
            </footer>
        </div>
    );
}

export default LinkChecker;
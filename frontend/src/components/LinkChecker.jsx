import { useState } from "react";

const API_BASE = "http://localhost:8000";
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

function StatusBadge({ isAlive, statusCode }) {
    if (isAlive) {
        return (
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-700">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block"></span>
                {statusCode} OK
            </span>
        );
    }
    return (
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold bg-red-100 text-red-700">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block"></span>
            {statusCode || "Error"}
        </span>
    );
}

function ResultCard({ result }) {
    return (
        <div className={`rounded-xl border p-4 shadow-sm transition-all ${result.is_alive ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}`}>
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-gray-800 truncate font-medium">{result.url}</p>
                    {result.redirect_url && (
                        <p className="text-xs text-gray-500 mt-1 flex items-center gap-1">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                            </svg>
                            Redirected to: <span className="font-mono">{result.redirect_url}</span>
                        </p>
                    )}
                    {result.error && (
                        <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                            </svg>
                            {result.error}
                        </p>
                    )}
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                    {result.response_time_ms && (
                        <span className="text-xs text-gray-500">{result.response_time_ms}ms</span>
                    )}
                    <StatusBadge isAlive={result.is_alive} statusCode={result.status_code} />
                </div>
            </div>
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
        } catch (e) {
            setError("Failed to connect to backend. Make sure it's running on port 8000.");
            setLoading(false);
        }
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
        } catch (e) {
            setError(e.message || "Failed to connect to backend. Make sure it's running on port 8000.");
        } finally {
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
    };

    return (
        <main className="max-w-4xl mx-auto px-4 py-10">
            <div className="text-center mb-10">
                <h2 className="text-4xl font-serif font-bold text-gray-800 mb-3">TrustPulse</h2>
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
                        <label className="block text-sm font-semibold text-gray-700 mb-3">Enter URLs (max 20)</label>
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
                                            className="text-gray-400 hover:text-red-500 px-2 transition-colors text-lg"
                                        >×</button>
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
                        <p className="text-xs text-gray-400 mb-3">{bulkText.length}/{MAX_BULK_LENGTH} characters</p>
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
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                        </svg>
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
                                <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                                Checking links...
                            </>
                        ) : (
                            <>
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
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
                    <div className="grid grid-cols-3 gap-4 mb-6">
                        <div className="bg-white border border-gray-200 rounded-xl p-4 text-center shadow-sm">
                            <p className="text-3xl font-bold text-gray-800">{results.summary.total}</p>
                            <p className="text-sm text-gray-500 font-medium mt-1">Total Links</p>
                        </div>
                        <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center shadow-sm">
                            <p className="text-3xl font-bold text-green-600">{results.summary.alive}</p>
                            <p className="text-sm text-green-600 font-medium mt-1">Alive</p>
                        </div>
                        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-center shadow-sm">
                            <p className="text-3xl font-bold text-red-600">{results.summary.dead}</p>
                            <p className="text-sm text-red-600 font-medium mt-1">Broken</p>
                        </div>
                    </div>

                    {results.skipped?.length > 0 && (
                        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-xl text-yellow-700 text-sm">
                            <strong>{results.skipped.length} URL(s) were skipped</strong> due to invalid format or security restrictions.
                        </div>
                    )}

                    <div className="space-y-3">
                        <h3 className="font-semibold text-gray-700 text-sm uppercase tracking-wide">Individual Results</h3>
                        {results.results.map((result, i) => (
                            <ResultCard key={i} result={result} />
                        ))}
                    </div>
                </div>
            )}
        </main>
    );
}

export default LinkChecker;
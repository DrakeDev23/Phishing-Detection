import { useState } from "react";
import { ShieldCheck, Link2, Sparkles } from "lucide-react";

const features = [
    {
        icon: ShieldCheck,
        title: "Phishing Detection",
        desc: "Heuristic analysis, Google Safe Browsing, and VirusTotal integration catch threats before you click.",
        stat: "3 signal sources",
        code: "01",
    },
    {
        icon: Link2,
        title: "Link Health",
        desc: "Verify if links are alive or broken with real-time HTTP status tracking and redirect tracing.",
        stat: "Live status checks",
        code: "02",
    },
    {
        icon: Sparkles,
        title: "AI Analysis",
        desc: "Plain language security summaries powered by AI, so the verdict is never a guess.",
        stat: "Instant summaries",
        code: "03",
    },
];

function About() {
    const [active, setActive] = useState(0);
    const current = features[active];

    return (
        <section id="about" className="border-t border-[#262D3D] bg-[#10141C] py-24 px-4">
            <div className="max-w-5xl mx-auto">
                <p className="text-xs font-mono uppercase tracking-[0.3em] text-[#6C93FF] mb-3 text-center">
                    Why TrvstPulse
                </p>
                <h3 className="text-3xl md:text-4xl font-serif font-bold text-[#E7EAF0] mb-14 text-center">
                    Built for verification, not guesswork
                </h3>

                <div className="grid md:grid-cols-[280px_1fr] border border-[#262D3D] rounded-xl overflow-hidden bg-[#171C27]">
                    <div className="border-b md:border-b-0 md:border-r border-[#262D3D]">
                        {features.map((feature, idx) => {
                            const isActive = active === idx;
                            return (
                                <button
                                    key={idx}
                                    onMouseEnter={() => setActive(idx)}
                                    onClick={() => setActive(idx)}
                                    className={`w-full flex items-center gap-4 px-6 py-5 text-left border-l-2 transition-all duration-300 ${isActive
                                            ? "border-l-[#6C93FF] bg-[#1B2230]"
                                            : "border-l-transparent hover:bg-[#1B2230]/60"
                                        }`}
                                >
                                    <span
                                        className={`font-mono text-xs transition-colors duration-300 ${isActive ? "text-[#6C93FF]" : "text-[#4C5468]"
                                            }`}
                                    >
                                        {feature.code}
                                    </span>
                                    <span
                                        className={`text-sm font-medium transition-colors duration-300 ${isActive ? "text-[#E7EAF0]" : "text-[#8B93A7]"
                                            }`}
                                    >
                                        {feature.title}
                                    </span>
                                </button>
                            );
                        })}
                    </div>

                    <div className="relative p-10 py-16 flex flex-col justify-center overflow-hidden">
                        <div
                            className="absolute inset-0 opacity-[0.03] pointer-events-none"
                            style={{
                                backgroundImage:
                                    "linear-gradient(#6C93FF 1px, transparent 1px), linear-gradient(90deg, #6C93FF 1px, transparent 1px)",
                                backgroundSize: "28px 28px",
                            }}
                        />

                        <div key={active} className="relative animate-[fadein_0.35s_ease-out]">
                            <div className="w-12 h-12 flex items-center justify-center mb-6 border border-[#6C93FF] text-[#6C93FF] rounded-md bg-[#6C93FF]/10">
                                <current.icon className="h-5 w-5" strokeWidth={2} />
                            </div>

                            <h4 className="font-serif font-bold text-2xl text-[#E7EAF0] mb-3">
                                {current.title}
                            </h4>

                            <p className="text-[#8B93A7] leading-relaxed max-w-md mb-6">
                                {current.desc}
                            </p>

                            <div className="inline-flex items-center gap-2 text-[11px] font-mono uppercase tracking-wider text-[#6C93FF] border border-[#6C93FF]/30 rounded-full px-3 py-1.5">
                                <span className="h-1.5 w-1.5 rounded-full bg-[#6C93FF] animate-pulse" />
                                {current.stat}
                            </div>
                        </div>

                        <div className="absolute bottom-6 right-8 flex gap-1.5">
                            {features.map((_, idx) => (
                                <span
                                    key={idx}
                                    className={`h-1 rounded-full transition-all duration-300 ${active === idx ? "w-6 bg-[#6C93FF]" : "w-1 bg-[#262D3D]"
                                        }`}
                                />
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes fadein {
                    from { opacity: 0; transform: translateY(6px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            `}</style>
        </section>
    );
}

export default About;
import { Icons } from "./Icons";

const features = [
    { icon: Icons.Shield, title: "Phishing Detection", desc: "Heuristic analysis, Google Safe Browsing, and VirusTotal integration" },
    { icon: Icons.Check, title: "Link Health", desc: "Verify if links are alive or broken with HTTP status tracking" },
    { icon: Icons.Sparkle, title: "AI Analysis", desc: "Plain language security summaries powered by Gemini AI" },
];

function About() {
    return (
        <section id="about" className="border-t border-slate-700/30 py-12 px-4 bg-slate-900/30">
            <div className="max-w-5xl mx-auto">
                <h3 className="text-2xl font-bold text-slate-100 mb-8 text-center">Why Use TrvstPulse?</h3>
                <div className="grid md:grid-cols-3 gap-6">
                    {features.map((feature, idx) => (
                        <div key={idx} className="glass-dark p-6 hover:border-slate-500/50 transition-all">
                            <div className="w-10 h-10 bg-slate-700/40 rounded-lg flex items-center justify-center mb-4 border border-slate-600/40">
                                <feature.icon className="h-5 w-5 text-blue-300" />
                            </div>
                            <h4 className="font-bold text-slate-100 mb-2">{feature.title}</h4>
                            <p className="text-xs text-slate-400 leading-relaxed">{feature.desc}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}

export default About;
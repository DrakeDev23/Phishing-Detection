import { Icons } from "./Icons";

const features = [
    { icon: Icons.Shield, title: "Phishing Detection", desc: "Heuristic analysis, Google Safe Browsing, and VirusTotal integration" },
    { icon: Icons.Check, title: "Link Health", desc: "Verify if links are alive or broken with HTTP status tracking" },
    { icon: Icons.Sparkle, title: "AI Analysis", desc: "Plain language security summaries powered by  AI" },
];

function About() {
    return (
        <section id="about" className="border-t border-[#262D3D] bg-[#10141C] py-16 px-4">
            <div className="max-w-5xl mx-auto">
                <p className="text-xs font-mono uppercase tracking-widest text-[#6C93FF] mb-2 text-center">Why TrvstPulse</p>
                <h3 className="text-3xl font-serif font-bold text-[#E7EAF0] mb-10 text-center">Built for verification, not guesswork</h3>
                <div className="grid md:grid-cols-3 gap-px bg-[#262D3D] border border-[#262D3D]">
                    {features.map((feature, idx) => (
                        <div key={idx} className="bg-[#171C27] p-7">
                            <div className="w-9 h-9 flex items-center justify-center mb-5 border border-[#6C93FF] text-[#6C93FF] rounded-md">
                                <feature.icon className="h-4 w-4" />
                            </div>
                            <h4 className="font-serif font-bold text-[#E7EAF0] mb-2">{feature.title}</h4>
                            <p className="text-sm text-[#8B93A7] leading-relaxed">{feature.desc}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}

export default About;
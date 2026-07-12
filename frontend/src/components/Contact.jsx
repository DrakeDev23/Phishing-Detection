import { Icons } from "./Icons";

const CONTACT_EMAIL = "hello@trvstpulse.com";

const socialLinks = [
    { icon: Icons.Facebook, label: "Facebook", href: "https://facebook.com/trvstpulse" },
    { icon: Icons.Github, label: "GitHub", href: "https://github.com/trvstpulse" },
    { icon: Icons.Linkedin, label: "LinkedIn", href: "https://linkedin.com/company/trvstpulse" },
];

function Contact() {
    return (
        <section id="contact" className="border-t border-slate-700/30 bg-slate-900/50 py-12 px-4">
            <div className="max-w-5xl mx-auto text-center">
                <h3 className="text-2xl font-bold text-slate-100 mb-3">Get in Touch</h3>
                <p className="text-sm text-slate-400 mb-6">Questions, feedback, or a link you want us to look at.</p>

                <a
                    href={`mailto:${CONTACT_EMAIL}`}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700/40 border border-slate-600/40 text-slate-200 text-sm font-medium hover:border-blue-500/40 hover:text-blue-300 transition-all"
                >
                    <Icons.Mail className="h-4 w-4" />
                    {CONTACT_EMAIL}
                </a>

                <div className="flex items-center justify-center gap-3 mt-6">
                    {socialLinks.map((link, idx) => (
                        <a
                            key={idx}
                            href={link.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label={link.label}
                            className="w-10 h-10 flex items-center justify-center rounded-lg bg-slate-700/40 border border-slate-600/40 text-slate-300 hover:border-blue-500/40 hover:text-blue-300 transition-all"
                        >
                            <link.icon className="h-4 w-4" />
                        </a>
                    ))}
                </div>

                <p className="text-xs text-slate-500 mt-8">© {new Date().getFullYear()} TrvstPulse. Advanced link security analysis.</p>
            </div>
        </section>
    );
}

export default Contact;
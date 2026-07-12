import { Icons } from "./Icons";

const CONTACT_EMAIL = "maccogoth@.com";

const socialLinks = [
    { icon: Icons.Facebook, label: "Facebook", href: "https://web.facebook.com/stephen.mart.98" },
    { icon: Icons.Github, label: "GitHub", href: "https://github.com/DrakeDev23" },
    { icon: Icons.Linkedin, label: "LinkedIn", href: "https://www.linkedin.com/in/zedrick-dwyn-manguilimotan-85540b3b2/" },
];

function Contact() {
    return (
        <section id="contact" className="border-t border-[#262D3D] bg-[#141B2E] py-16 px-4">
            <div className="max-w-5xl mx-auto text-center">
                <p className="text-xs font-mono uppercase tracking-widest text-[#6C93FF] mb-2">Get in Touch</p>
                <h3 className="text-3xl font-serif font-bold text-[#E7EAF0] mb-3">Talk to the team</h3>
                <p className="text-sm text-[#8B93A7] mb-8">Questions, feedback, or a link you want us to look at.</p>

                <a
                    href={`mailto:${CONTACT_EMAIL}`}
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md border border-[#6C93FF] text-[#6C93FF] text-sm font-medium font-mono hover:bg-[#6C93FF] hover:text-[#10141C] transition-colors"
                >
                    <Icons.Mail className="h-4 w-4" />
                    {CONTACT_EMAIL}
                </a>

                <div className="flex items-center justify-center gap-3 mt-8">
                    {socialLinks.map((link, idx) => (
                        <a
                            key={idx}
                            href={link.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label={link.label}
                            className="w-10 h-10 flex items-center justify-center rounded-md border border-[#262D3D] bg-[#171C27] text-[#8B93A7] hover:border-[#6C93FF] hover:text-[#6C93FF] transition-colors"
                        >
                            <link.icon className="h-4 w-4" />
                        </a>
                    ))}
                </div>

                <p className="text-xs text-[#8B93A7] mt-10">© {new Date().getFullYear()} TrvstPulse. Advanced link security analysis.</p>
            </div>
        </section>
    );
}

export default Contact;
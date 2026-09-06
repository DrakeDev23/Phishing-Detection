import { Mail } from "lucide-react";
import { FacebookIcon, GithubIcon, LinkedinIcon } from "./SocialIcons";

const CONTACT_EMAIL = "maccogoth@gmail.com";

const socialLinks = [
    { icon: FacebookIcon, label: "Facebook", href: "https://web.facebook.com/stephen.mart.98" },
    { icon: GithubIcon, label: "GitHub", href: "https://github.com/DrakeDev23" },
    { icon: LinkedinIcon, label: "LinkedIn", href: "https://www.linkedin.com/in/zedrick-dwyn-manguilimotan-85540b3b2/" },
];

function Contact() {
    return (
        <section id="contact" className="border-t border-[#262D3D] bg-[#141B2E] py-24 px-4">
            <div className="max-w-5xl mx-auto grid md:grid-cols-2 gap-12 md:gap-0">
                <div className="md:pr-16 md:border-r border-[#262D3D] flex flex-col justify-center">
                    <p className="text-xs font-mono uppercase tracking-[0.3em] text-[#6C93FF] mb-4">
                        Get in touch
                    </p>
                    <h3 className="text-3xl md:text-4xl font-serif font-bold text-[#E7EAF0] leading-tight mb-4">
                        Questions, feedback, or a link worth a second look.
                    </h3>
                    <p className="text-sm text-[#8B93A7] leading-relaxed max-w-sm">
                        Reach out directly or find TrvstPulse across the usual places below.
                    </p>
                </div>

                <div className="md:pl-16 flex flex-col justify-center gap-8">
                    <a
                        href={`mailto:${CONTACT_EMAIL}`}
                        className="group flex items-center gap-3"
                    >
                        <Mail className="h-4 w-4 text-[#4C5468] transition-colors duration-300 group-hover:text-[#6C93FF]" />
                        <span className="text-xl font-mono text-[#E7EAF0] border-b border-transparent transition-colors duration-300 group-hover:border-[#6C93FF] group-hover:text-[#6C93FF]">
                            {CONTACT_EMAIL}
                        </span>
                    </a>

                    <div className="flex flex-col gap-1">
                        {socialLinks.map((link, idx) => (
                            <a
                                key={idx}
                                href={link.href}
                                target="_blank"
                                rel="noopener noreferrer"
                                aria-label={link.label}
                                className="group flex items-center gap-3 py-2 text-sm text-[#8B93A7] transition-colors duration-300 hover:text-[#E7EAF0]"
                            >
                                <span className="h-px w-4 bg-[#4C5468] transition-all duration-300 group-hover:w-8 group-hover:bg-[#6C93FF]" />
                                <link.icon className="h-4 w-4 text-[#4C5468] transition-colors duration-300 group-hover:text-[#6C93FF]" />
                                {link.label}
                            </a>
                        ))}
                    </div>

                    <p className="text-xs text-[#4C5468] pt-4 border-t border-[#262D3D]">
                        © {new Date().getFullYear()} TrvstPulse. Advanced link security analysis.
                    </p>
                </div>
            </div>
        </section>
    );
}

export default Contact;
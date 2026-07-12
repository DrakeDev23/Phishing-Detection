import { useState } from "react";
import { Menu, ShieldCheck, X } from "lucide-react";

function Header(props) {
    const [menuOpen, setMenuOpen] = useState(false);

    const navItems = [
        { label: "Home", href: "/" },
        { label: "About", action: "about" },
        { label: "Contact", action: "contact" },
    ];

    const navItemClasses =
        "inline-flex items-center px-3 py-2 text-sm font-medium text-[#8B93A7] hover:text-[#E7EAF0] border-b-2 border-transparent hover:border-[#6C93FF] transition-colors appearance-none bg-transparent font-inherit leading-none";

    const mobileNavItemClasses =
        "flex w-full items-center px-4 py-3 text-sm font-medium text-[#8B93A7] hover:text-[#E7EAF0] hover:bg-white/5 border-l-2 border-transparent hover:border-[#6C93FF] transition-colors appearance-none bg-transparent font-inherit leading-none text-left";

    const scrollTo = (id) => {
        const el = document.getElementById(id);
        if (el) {
            el.scrollIntoView({ behavior: "smooth", block: "start" });
        }
        setMenuOpen(false);
    };

    return (
        <header className="sticky top-0 z-50 bg-[#10141C] border-b border-[#262D3D]">
            <div className="flex justify-between h-16 items-center px-6 max-w-7xl mx-auto">
                <div className="flex items-center gap-3">
                    <div className="w-9 h-9 flex items-center justify-center rounded-md border border-[#6C93FF] text-[#6C93FF]">
                        <ShieldCheck className="w-4 h-4" strokeWidth={1.75} />
                    </div>
                    <div>
                        <h1 className="text-lg font-serif font-bold text-[#E7EAF0] leading-tight">
                            {props.name}
                        </h1>
                        <p className="text-[11px] font-mono uppercase tracking-wider text-[#8B93A7]">Security Check</p>
                    </div>
                </div>

                <nav className="hidden md:block">
                    <ul className="flex gap-1 items-center">
                        {navItems.map((item, idx) => (
                            <li key={idx} className="flex">
                                {item.href ? (
                                    <a href={item.href} className={navItemClasses}>
                                        {item.label}
                                    </a>
                                ) : (
                                    <button
                                        onClick={() => scrollTo(item.action)}
                                        className={navItemClasses}
                                    >
                                        {item.label}
                                    </button>
                                )}
                            </li>
                        ))}
                    </ul>
                </nav>

                <button
                    className="md:hidden p-2 rounded-md text-[#8B93A7] hover:text-[#E7EAF0] hover:bg-white/5 transition-colors"
                    onClick={() => setMenuOpen(!menuOpen)}
                    aria-label="Toggle menu"
                >
                    {menuOpen ? (
                        <X className="w-6 h-6" strokeWidth={1.75} />
                    ) : (
                        <Menu className="w-6 h-6" strokeWidth={1.75} />
                    )}
                </button>
            </div>

            <div
                className={`md:hidden overflow-hidden transition-all duration-300 ease-in-out ${menuOpen ? "max-h-48 opacity-100" : "max-h-0 opacity-0"
                    }`}
            >
                <nav className="bg-[#10141C] px-2 py-2 border-t border-[#262D3D]">
                    <ul className="flex flex-col gap-1">
                        {navItems.map((item, idx) => (
                            <li key={idx}>
                                {item.href ? (
                                    <a href={item.href}
                                        onClick={() => setMenuOpen(false)}
                                        className={mobileNavItemClasses}
                                    >
                                        {item.label}
                                    </a>
                                ) : (
                                    <button
                                        onClick={() => scrollTo(item.action)}
                                        className={mobileNavItemClasses}
                                    >
                                        {item.label}
                                    </button>
                                )}
                            </li>
                        ))}
                    </ul>
                </nav>
            </div>
        </header>
    );
}

export default Header;

import { useState } from "react";

function Header(props) {
    const [menuOpen, setMenuOpen] = useState(false);

    const navItems = [
        { label: "Home", href: "/" },
        { label: "About", action: "about" },
        { label: "Contact", action: "contact" },
    ];

    const navItemClasses =
        "inline-flex items-center px-3 py-2 text-sm font-medium text-[#5B6B85] hover:text-[#0B1220] border-b-2 border-transparent hover:border-[#1B4DFF] transition-colors appearance-none bg-transparent font-inherit leading-none";

    const mobileNavItemClasses =
        "flex w-full items-center px-4 py-3 text-sm font-medium text-[#5B6B85] hover:text-[#0B1220] hover:bg-[#F1F5FF] border-l-2 border-transparent hover:border-[#1B4DFF] transition-colors appearance-none bg-transparent font-inherit leading-none text-left";

    const scrollTo = (id) => {
        const el = document.getElementById(id);
        if (el) {
            el.scrollIntoView({ behavior: "smooth", block: "start" });
        }
        setMenuOpen(false);
    };

    return (
        <header className="sticky top-0 z-50 bg-white border-b border-[#E2E8F5]">
            <div className="flex justify-between h-16 items-center px-6 max-w-7xl mx-auto">
                <div className="flex items-center gap-3">
                    <div className="w-9 h-9 flex items-center justify-center rounded-md border border-[#1B4DFF] text-[#1B4DFF]">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M9 12l2 2 4-4" />
                        </svg>
                    </div>
                    <div>
                        <h1 className="text-lg font-serif font-bold text-[#0B1220] leading-tight">
                            {props.name}
                        </h1>
                        <p className="text-[11px] font-mono uppercase tracking-wider text-[#5B6B85]">Security Check</p>
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
                    className="md:hidden p-2 rounded-md text-[#5B6B85] hover:text-[#0B1220] hover:bg-[#F1F5FF] transition-colors"
                    onClick={() => setMenuOpen(!menuOpen)}
                    aria-label="Toggle menu"
                >
                    {menuOpen ? (
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    ) : (
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M4 6h16M4 12h16M4 18h16" />
                        </svg>
                    )}
                </button>
            </div>

            <div
                className={`md:hidden overflow-hidden transition-all duration-300 ease-in-out ${menuOpen ? "max-h-48 opacity-100" : "max-h-0 opacity-0"
                    }`}
            >
                <nav className="bg-white px-2 py-2 border-t border-[#E2E8F5]">
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
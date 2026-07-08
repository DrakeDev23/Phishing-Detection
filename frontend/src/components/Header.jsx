import { useState } from "react";

function Header(props) {
    const [menuOpen, setMenuOpen] = useState(false);

    const scrollTo = (id) => {
        const el = document.getElementById(id);
        if (el) {
            el.scrollIntoView({ behavior: "smooth", block: "start" });
        }
        setMenuOpen(false);
    };

    return (
        <header className="sticky top-0 z-50 backdrop-blur-md bg-slate-900/30 border-b border-slate-700/30">
            <div className="flex justify-between h-16 items-center px-6 max-w-7xl mx-auto">
                <div className="flex items-center gap-3 group cursor-pointer">
                    <div className="p-2 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 group-hover:shadow-lg group-hover:shadow-blue-500/50 transition-all">
                        <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
                        </svg>
                    </div>
                    <div>
                        <h1 className="text-xl font-bold text-white group-hover:text-blue-300 transition-colors">
                            {props.name}
                        </h1>
                        <p className="text-xs text-slate-400">Security Check</p>
                    </div>
                </div>

                <nav className="hidden md:block">
                    <ul className="flex gap-1">
                        {[
                            { label: "Home", href: "/" },
                            { label: "About", action: "about" },
                            { label: "Contact", action: "contact" },
                        ].map((item, idx) => (
                            <li key={idx}>
                                {item.href ? (
                                    <a
                                        href={item.href}
                                        className="px-4 py-2 text-slate-300 hover:text-white transition-colors rounded-lg hover:bg-slate-700/50"
                                    >
                                        {item.label}
                                    </a>
                                ) : (
                                    <button
                                        onClick={() => scrollTo(item.action)}
                                        className="px-4 py-2 text-slate-300 hover:text-white transition-colors rounded-lg hover:bg-slate-700/50"
                                    >
                                        {item.label}
                                    </button>
                                )}
                            </li>
                        ))}
                    </ul>
                </nav>

                <button
                    className="md:hidden p-2 rounded-lg text-slate-300 hover:text-white hover:bg-slate-700/50 transition-all"
                    onClick={() => setMenuOpen(!menuOpen)}
                    aria-label="Toggle menu"
                >
                    {menuOpen ? (
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    ) : (
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                        </svg>
                    )}
                </button>
            </div>

            <div
                className={`md:hidden overflow-hidden transition-all duration-300 ease-in-out ${
                    menuOpen ? "max-h-48 opacity-100" : "max-h-0 opacity-0"
                }`}
            >
                <nav className="bg-slate-800/50 backdrop-blur-md px-6 py-4 border-t border-slate-700/30">
                    <ul className="flex flex-col gap-2">
                        {[
                            { label: "Home", href: "/" },
                            { label: "About", action: "about" },
                            { label: "Contact", action: "contact" },
                        ].map((item, idx) => (
                            <li key={idx}>
                                {item.href ? (
                                    <a
                                        href={item.href}
                                        onClick={() => setMenuOpen(false)}
                                        className="block px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
                                    >
                                        {item.label}
                                    </a>
                                ) : (
                                    <button
                                        onClick={() => scrollTo(item.action)}
                                        className="block w-full text-left px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
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
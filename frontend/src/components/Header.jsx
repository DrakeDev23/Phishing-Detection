import { useState } from "react";

function Header(props) {
    const [menuOpen, setMenuOpen] = useState(false);

    return (
        <header className="bg-blue-500 shadow-md shadow-gray-500">
            <div className="flex justify-between h-16 items-center p-5">
                <div className="flex items-center gap-2">
                    <img src="Logo.png" className="w-10 h-10 md:w-16 md:h-16" alt="Logo" />
                    <h1 className="text-xl md:text-2xl font-serif font-bold text-white">
                        {props.name}
                    </h1>
                </div>

                <nav className="hidden md:block">
                    <ul className="flex gap-5 text-xl text-white font-medium">
                        <li><a href="/" className="hover:text-blue-100 transition-colors">Home</a></li>
                        <li><a href="/about" className="hover:text-blue-100 transition-colors">About</a></li>
                        <li><a href="/contact" className="hover:text-blue-100 transition-colors">Contact</a></li>
                    </ul>
                </nav>

                <button
                    className="md:hidden text-white focus:outline-none"
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

            {menuOpen && (
                <nav className="md:hidden bg-blue-600 px-5 pb-4">
                    <ul className="flex flex-col gap-3 text-lg text-white font-medium">
                        <li><a href="/" className="block hover:text-blue-100 transition-colors">Home</a></li>
                        <li><a href="/about" className="block hover:text-blue-100 transition-colors">About</a></li>
                        <li><a href="/contact" className="block hover:text-blue-100 transition-colors">Contact</a></li>
                    </ul>
                </nav>
            )}
        </header>
    );
}

export default Header;
function Header(props) {
    return (
        <header className="flex bg-blue-500 justify-between h-16 items-center shadow-md shadow-gray-500 p-5">
            <div className="flex items-center gap-2">
                <img src="Logo.png" className="w-16 h-16"></img>
                <h1 className="text-2xl font-serif font-bold text-white">{props.name}</h1>
            </div>
            <nav>
                <ul className="flex gap-5 p-5 text-xl text-white font-medium">
                    <li><a href="/" className="hover:text-blue-100 transition-colors">Home</a></li>
                    <li><a href="/about" className="hover:text-blue-100 transition-colors">About</a></li>
                    <li><a href="/contact" className="hover:text-blue-100 transition-colors">Contact</a></li>
                </ul>
            </nav>
        </header>
    )
}

export default Header;
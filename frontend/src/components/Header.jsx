
function Header(props) {
    return (
        <header className="flex bg-blue-500 justify-between h-16 items-center shadow-md shadow-gray-500 p-5">
            <div className="flex items-center gap-2">
                <img src="/Logo.png" alt="logo" className="h-10" />
                <h1 className="text-2xl font-serif font-bold">{props.name}</h1>
            </div>
            <nav>
                <ul className="flex gap-5 p-5 text-xl">
                    <li><a href="/">Home</a></li>
                    <li><a href="/">About</a></li>
                    <li><a href="/">Contact</a></li>
                </ul>
            </nav>
        </header>
    )
}

export default Header;
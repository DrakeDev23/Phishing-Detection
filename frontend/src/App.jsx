import Header from "./components/Header";
import LinkChecker from "./components/LinkChecker";

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header name="TrvstPulse" />
      <LinkChecker />
    </div>
  );
}

export default App;
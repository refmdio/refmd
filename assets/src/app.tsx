import { Router, Route } from "@solidjs/router";
import "./app.css";

function Home() {
  return <div class="p-4">RefMD</div>;
}

export default function App() {
  return (
    <Router>
      <Route path="/" component={Home} />
    </Router>
  );
}

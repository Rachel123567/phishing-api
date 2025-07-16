import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import axios from 'axios';
import './App.css';
import logo from './rp-logo.png';

function App() {
  return (
    <Router>
      <div className="app">
        <Navbar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/about" element={<About />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/recent" element={<RecentChecks />} />
        </Routes>
        <Footer />
      </div>
    </Router>
  );
}

function Navbar() {
  return (
    <nav className="navbar">
      <div className="container brand-container">
        <div className="brand-logo">
          <img src={logo} alt="RP Logo" className="logo" />
          <Link to="/" className="brand">PHISHING DETECTOR</Link>
        </div>
        <div className="nav-links">
          <Link to="/">Home</Link>
          <Link to="/about">About</Link>
          <Link to="/contact">Contact</Link>
          <Link to="/recent">Recent Checks</Link>
        </div>
      </div>
    </nav>
  );
}

function Home() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const checkUrl = async (e) => {
    e.preventDefault();
    if (!url) {
      setError('Please enter a URL to check');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(
        'https://phishing-api-mb1j.onrender.com/predict',
        { url: url },
        { headers: { 'Content-Type': 'application/json' } }
      );

      if (response.data.error) {
        throw new Error(response.data.error);
      }

      setResult(response.data);

      const recent = JSON.parse(localStorage.getItem('recentChecks') || '[]');
      localStorage.setItem(
        'recentChecks',
        JSON.stringify([response.data, ...recent.filter(r => r.url !== response.data.url)].slice(0, 10))
      );
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to check URL. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="home">
      <h1>Phishing Detector</h1>
      <div className="card">
        <form onSubmit={checkUrl}>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter URL (e.g., https://example.com)"
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? (
              <>
                <span className="spinner"></span> Checking...
              </>
            ) : (
              'Check URL'
            )}
          </button>
        </form>

        {error && <div className="error">{error}</div>}

        {result && (
          <div className="result">
            <h3>Analysis Result</h3>
            <p>
              <strong>URL:</strong>{' '}
              <a href={result.url} target="_blank" rel="noopener noreferrer">
                {result.url}
              </a>
            </p>
            <div className={`status ${result.is_phishing ? 'phishing' : 'safe'}`}>
              {result.is_phishing ? '⚠️ PHISHING DETECTED' : '✅ SAFE WEBSITE'}
            </div>

            <div className="risk-level">
              <span>Risk Level:</span>
              <div className="progress-bar">
                <div
                  className="progress"
                  style={{ width: `${Math.round(result.probability * 100)}%` }}
                >
                  {Math.round(result.probability * 100)}%
                </div>
              </div>
            </div>

            <p className="reason">
              <strong>Reason:</strong> {result.reason}
            </p>
            <p className="timestamp">
              <strong>Checked on:</strong> {result.timestamp}
            </p>

            {!result.is_phishing && (
              <div className="safe-box">
                <button onClick={() => window.open(result.url, '_blank')}>
                  Visit Website 🔗
                </button>
              </div>
            )}

            {result.is_phishing && (
              <div className="warning">
                <p>⚠️ Warning: This website appears to be a phishing attempt.</p>
                <p>🚫 Access is blocked to protect you from malicious content.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function About() {
  return (
    <div className="page">
      <h2>About the Phishing Detection System</h2>
      <p>This responsive web application is built to help individuals and Rwandan institutions detect phishing websites.</p>
      <p>
        It uses a hybrid detection system combining:
        <ul>
          <li><strong>Rule-based logic</strong> for immediate risks</li>
          <li><strong>ML model with 53 features</strong> for deeper prediction</li>
          <li><strong>Whitelist of trusted .rw domains</strong></li>
        </ul>
      </p>
      <p>
        It’s especially useful for users accessing official portals like <strong>Irembo</strong>, <strong>REB</strong>, <strong>RRA</strong>, etc.
      </p>
    </div>
  );
}

function Contact() {
  return (
    <div className="page">
      <h2>Contact Us</h2>
      <p>If you have questions or suggestions, feel free to get in touch.</p>
      <div style={{ marginTop: '1.5rem' }}>
        <h4>📞 Phone</h4>
        <p><a href="tel:+250789246013">+250 789 246 013</a></p>
        <h4>Email</h4>
        <p><a href="mailto:rtuyi883@gmail.com">rtuyi883@gmail.com</a></p>
        <h4>Office Hours</h4>
        <p>Monday – Friday, 8:00 AM to 6:00 PM (CAT)</p>
      </div>
    </div>
  );
}

function RecentChecks() {
  const recent = JSON.parse(localStorage.getItem('recentChecks') || '[]');

  return (
    <div className="page">
      <h2>Recent Checks</h2>
      {recent.length === 0 ? (
        <p>No recent checks available.</p>
      ) : (
        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
          <table className="recent-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>URL</th>
                <th>Checked On</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((item, index) => (
                <tr key={index}>
                  <td
                    style={{
                      color: item.is_phishing ? 'red' : 'green',
                      fontWeight: 'bold',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {item.is_phishing ? 'Phishing' : 'Legitimate'}
                  </td>
                  <td style={{ wordBreak: 'break-word' }}>
                    <a href={item.url} target="_blank" rel="noreferrer">{item.url}</a>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {item.timestamp}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <p>&copy; 2025 Phishing Detector. Designed by Rachel.</p>
    </footer>
  );
}

export default App;

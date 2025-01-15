import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Calendar from './components/Calendar';
import NewReservation from './components/NewReservation';
import { logout } from './services/auth';

const App: React.FC = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [username, setUsername] = useState<string | null>(null);
    const [locale, setLocale] = useState<'en' | 'pt'>('en');
    const [lastActivity, setLastActivity] = useState(Date.now());

    const handleLogin = (username: string) => {
        setIsAuthenticated(true);
        setUsername(username);
        setLastActivity(Date.now());
    };

    const handleLogout = () => {
        logout();
        setIsAuthenticated(false);
        setUsername(null);
    };

    const toggleLocale = () => {
        setLocale((prevLocale) => (prevLocale === 'en' ? 'pt' : 'en'));
    };

    const resetActivityTimer = () => {
        setLastActivity(Date.now());
    };

    useEffect(() => {
        const checkInactivity = () => {
            if (isAuthenticated && Date.now() - lastActivity > 15 * 60 * 1000) { // 15 minutes of inactivity
                handleLogout();
            }
        };

        const interval = setInterval(checkInactivity, 60 * 1000); // Check every minute

        const events = ['click', 'mousemove', 'keypress'];
        events.forEach(event => window.addEventListener(event, resetActivityTimer));

        return () => {
            clearInterval(interval);
            events.forEach(event => window.removeEventListener(event, resetActivityTimer));
        };
    }, [isAuthenticated, lastActivity]);

    return (
        <BrowserRouter>
            <div className="header">
                <div className="locale-toggle">
                    <button onClick={toggleLocale}>
                        {locale === 'en' ? 'PT' : 'EN'}
                    </button>
                </div>
                {isAuthenticated && (
                    <div className="user-info">
                        <span>{username}</span>
                        <button onClick={handleLogout}>Logout</button>
                    </div>
                )}
            </div>
            <Routes>
                <Route 
                    path="/" 
                    element={
                        isAuthenticated ? 
                        <Navigate to="/calendar" replace /> : 
                        <Login onLogin={(username) => handleLogin(username)} locale={locale} />
                    } 
                />
                <Route 
                    path="/calendar" 
                    element={
                        isAuthenticated ? 
                        <Calendar locale={locale} /> : 
                        <Navigate to="/" replace />
                    } 
                />
                <Route 
                    path="/new-reservation" 
                    element={
                        isAuthenticated ? 
                        <NewReservation locale={locale} username={username || ''} /> : 
                        <Navigate to="/" replace />
                    } 
                />
            </Routes>
        </BrowserRouter>
    );
};

export default App;
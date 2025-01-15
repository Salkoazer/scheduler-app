import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login } from '../services/auth';
import translations from '../locales';
import './Login.css';

interface LoginProps {
  onLogin: (username: string) => void;
  locale: 'en' | 'pt';
}

const Login: React.FC<LoginProps> = ({ onLogin, locale }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const success = await login({ username, password });
            if (success) {
                onLogin(username);
                navigate('/calendar');
            } else {
                setError(translations[locale].invalidCredentials);
            }
        } catch (err) {
            setError(translations[locale].invalidCredentials);
        }
    };

    const t = translations[locale];

    return (
        <div className="login-container">
            <form className="login-box" onSubmit={handleSubmit}>
                <div className="form-group">
                    <label>{t.username}</label>
                    <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                    />
                </div>
                <div className="form-group">
                    <label>{t.password}</label>
                    <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                    />
                </div>
                {error && <p style={{ color: 'red' }}>{error}</p>}
                <button type="submit">{t.login}</button>
            </form>
        </div>
    );
};

export default Login;
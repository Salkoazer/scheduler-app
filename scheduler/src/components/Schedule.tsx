import React, { useState } from 'react';

const Schedule: React.FC = () => {
    const [showTitle, setShowTitle] = useState('');
    const [showDate, setShowDate] = useState('');
    const [showTime, setShowTime] = useState('');

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        // Logic to schedule the show goes here
    };

    return (
        <div>
            <h2>Schedule a Show</h2>
            <form onSubmit={handleSubmit}>
                <div>
                    <label>
                        Show Title:
                        <input
                            type="text"
                            value={showTitle}
                            onChange={(e) => setShowTitle(e.target.value)}
                            required
                        />
                    </label>
                </div>
                <div>
                    <label>
                        Show Date:
                        <input
                            type="date"
                            value={showDate}
                            onChange={(e) => setShowDate(e.target.value)}
                            required
                        />
                    </label>
                </div>
                <div>
                    <label>
                        Show Time:
                        <input
                            type="time"
                            value={showTime}
                            onChange={(e) => setShowTime(e.target.value)}
                            required
                        />
                    </label>
                </div>
                <button type="submit">Schedule Show</button>
            </form>
        </div>
    );
};

export default Schedule;
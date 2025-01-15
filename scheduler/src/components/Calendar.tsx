import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Calendar.css';
import enTranslations from '../locales/en.json';
import ptTranslations from '../locales/pt.json';
import { Reservation } from '../types/index';
import { fetchReservations } from '../services/reservations';

interface Translations {
    calendar: string;
    prevMonth: string;
    nextMonth: string;
    reservationDay: string;
    notes: string;
    newReservation: string;
    close: string;
    activeReservations: string;
    inactiveReservations: string;
    // add other translation keys here
}

interface CalendarProps {
    locale: 'en' | 'pt';
}

const Calendar: React.FC<CalendarProps> = ({ locale }) => {
    const [currentDate, setCurrentDate] = useState(new Date());
    const [selectedDay, setSelectedDay] = useState<number | null>(null);
    const [reservations, setReservations] = useState<Reservation[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [selectedReservations, setSelectedReservations] = useState<Reservation[]>([]);
    const [selectedRoom, setSelectedRoom] = useState<string>('room 1');
    const [selectedDate, setSelectedDate] = useState<Date | null>(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    const daysInMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0).getDate();
    const daysArray = Array.from({ length: daysInMonth }, (_, i) => i + 1);

    useEffect(() => {
        const startOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1).toISOString();
        const endOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0).toISOString();

        const loadReservations = async () => {
            try {
                const fetchedReservations = await fetchReservations(startOfMonth, endOfMonth);
                setReservations(fetchedReservations);
            } catch (error) {
                console.error('Error fetching reservations:', error);
                setError('Failed to fetch reservations');
            } finally {
                setLoading(false);
            }
        };

        loadReservations();
    }, [currentDate]);

    const handlePrevMonth = () => {
        setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() - 1, 1));
    };

    const handleNextMonth = () => {
        setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 1));
    };

    const handleDayClick = (day: number) => {
        setError(null);
        setSelectedDay(day);
        const dayReservations = reservations.filter(res => new Date(res.date).toDateString() === new Date(currentDate.getFullYear(), currentDate.getMonth(), day).toDateString() && res.room === selectedRoom);
        setSelectedReservations(dayReservations);
    };

    const closePopup = () => {
        setSelectedDay(null);
        setSelectedReservations([]);
        setError(null);
    };

    const translations: Translations = locale === 'en' ? enTranslations : ptTranslations;

    const isPastDate = (day: number) => {
        const selectedDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), day);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        return selectedDate < today;
    };

    const renderCalendarDays = () => {
        const days = [];
        const firstDayOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1).getDay();

        // Fill in the blanks for the days before the first day of the month
        for (let i = 0; i < firstDayOfMonth; i++) {
            days.push(<div key={`blank-${i}`} className="calendar-day blank"></div>);
        }

        for (let i = 1; i <= daysInMonth; i++) {
            const date = new Date(currentDate.getFullYear(), currentDate.getMonth(), i);
            const reservation = reservations.find(res => new Date(res.date).toDateString() === date.toDateString() && res.room === selectedRoom);

            days.push(
                <div
                    key={i}
                    className={`calendar-day ${isPastDate(i) ? 'past-date' : ''} ${reservation ? 'reservation' : ''}`}
                    onClick={() => handleDayClick(i)}
                >
                    <span className="day-number">{i}</span>
                    {reservation && <div className="reservation-name">{reservation.event}</div>}
                </div>
            );
        }

        return days;
    };

    const renderWeekDays = () => {
        const weekDays = [];
        const today = new Date();
        const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
        const dayOfWeek = firstDayOfMonth.getDay();

        for (let i = 0; i < 7; i++) {
            const day = new Date(firstDayOfMonth);
            day.setDate(day.getDate() + i - dayOfWeek);
            let weekDayName = day.toLocaleDateString(locale, { weekday: 'short' });
            if (locale === 'pt') {
                weekDayName = weekDayName.replace('.', ''); // Remove the full stop in Portuguese
            }
            weekDays.push(
                <div key={i} className="calendar-weekday">
                    {weekDayName.charAt(0).toUpperCase() + weekDayName.slice(1)}
                </div>
            );
        }

        return weekDays;
    };

    const handleNewReservation = (selectedDay: Date | null = null, fromPopup: boolean = false) => {
        const date = selectedDay ? new Date(selectedDay) : null;
        navigate('/new-reservation', { 
            state: { 
                selectedDate: date ? date.toISOString() : null,
                room: selectedRoom,
                fromCalendarBox: fromPopup // Only true when called from popup
            } 
        });
    };

    if (loading) {
        return <div>Loading...</div>;
    }

    if (error) {
        return <div>{error}</div>;
    }

    return (
        <div className="calendar-container">
            <div className="calendar-header">
                <button onClick={handlePrevMonth}>{translations.prevMonth}</button>
                <span>{currentDate.toLocaleString(locale, { month: 'long' }).charAt(0).toUpperCase() + currentDate.toLocaleString(locale, { month: 'long' }).slice(1)} {currentDate.getFullYear()}</span>
                <select value={selectedRoom} onChange={(e) => setSelectedRoom(e.target.value)}>
                    <option value="room 1">Room 1</option>
                    <option value="room 2">Room 2</option>
                </select>
                <button onClick={() => handleNewReservation(null, false)}>{translations.newReservation}</button>
                <button onClick={handleNextMonth}>{translations.nextMonth}</button>
            </div>
            <div className="calendar-weekdays">
                {renderWeekDays()}
            </div>
            <div className="calendar-grid">
                {renderCalendarDays()}
            </div>
            {selectedDay !== null && (
                <div className="popup">
                    <div className="popup-content">
                        <h2>{translations.reservationDay} - {selectedDay}/{currentDate.getMonth() + 1}/{currentDate.getFullYear()}</h2>
                        {error && <div className="error-message">{error}</div>}
                        <div className="popup-actions">
                            <button>{translations.notes}</button>
                            <button 
                                disabled={isPastDate(selectedDay) || selectedReservations.length > 0} 
                                onClick={() => handleNewReservation(
                                    new Date(currentDate.getFullYear(), currentDate.getMonth(), selectedDay),
                                    true
                                )}
                            >
                                {translations.newReservation}
                            </button>
                            <button onClick={closePopup}>{translations.close}</button>
                        </div>
                        <hr />
                        <section>
                            <h3>{translations.activeReservations}</h3>
                            {selectedReservations.filter(res => res.isActive).length > 0 ? (
                                selectedReservations.filter(res => res.isActive).map(res => (
                                    <div className="reservation" key={res._id}>
                                        <p>{res.event}</p>
                                        <p>{res.author}</p>
                                    </div>
                                ))
                            ) : (
                                <p>No active reservations</p>
                            )}
                        </section>
                        <hr />
                        <section>
                            <h3>{translations.inactiveReservations}</h3>
                            {selectedReservations.filter(res => !res.isActive).length > 0 ? (
                                selectedReservations.filter(res => !res.isActive).map(res => (
                                    <div className="reservation" key={res._id}>
                                        <p>{res.event}</p>
                                        <p>{res.author}</p>
                                    </div>
                                ))
                            ) : (
                                <p>No inactive reservations</p>
                            )}
                        </section>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Calendar;
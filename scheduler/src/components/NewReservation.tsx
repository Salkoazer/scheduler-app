import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import DatePicker from 'react-datepicker';
import "react-datepicker/dist/react-datepicker.css";
import './NewReservation.css';
import enTranslations from '../locales/en.json';
import ptTranslations from '../locales/pt.json';
import { enUS, pt, Locale } from 'date-fns/locale';
import { createReservation } from '../services/reservations';

interface NewReservationProps {
    locale: 'en' | 'pt';
    username?: string; // Add username prop
}

interface DateEntry {
    date: Date;
    type: string;
    event: string;  // Add this field
    hasNotes: boolean;
    notes: string;
}

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
    date: string;
    selectType: string;
    event: string;
    assembly: string;
    disassembly: string;
    others: string;
    placeholder: string;
    // ...other existing translation keys...
}

const NewReservation: React.FC<NewReservationProps> = ({ locale, username }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { room, selectedDate: initialSelectedDate, fromCalendarBox } = location.state || { 
        room: 'room 1', 
        selectedDate: null,
        fromCalendarBox: false 
    };

    // Properly parse the ISO string date
    const parsedInitialDate = initialSelectedDate ? new Date(initialSelectedDate) : null;
    
    const [selectedDate, setSelectedDate] = useState<Date | null>(parsedInitialDate);
    const [dateEntries, setDateEntries] = useState<DateEntry[]>(
        parsedInitialDate && fromCalendarBox ? [{
            date: parsedInitialDate,
            type: 'event',
            event: '',
            hasNotes: false,
            notes: ''
        }] : []
    );
    
    const [reservationNumber, setReservationNumber] = useState('');
    const [nif, setNif] = useState('');
    const [isValidNif, setIsValidNif] = useState<boolean | null>(null);
    const [producerName, setProducerName] = useState('');
    const [email, setEmail] = useState('');
    const [contact, setContact] = useState('');
    const [responsablePerson, setResponsablePerson] = useState('');
    const [event, setEvent] = useState('');
    const [eventClassification, setEventClassification] = useState('allAges'); // Set default value
    const [date, setDate] = useState<Date | null>(parsedInitialDate);
    const [type, setType] = useState('event');
    const [notes, setNotes] = useState('');
    const [author, setAuthor] = useState(username || ''); // Initialize with username prop

    const translations = locale === 'en' ? enTranslations : ptTranslations;

    const validateNif = (value: string) => {
        if (value.length === 9 && !isNaN(Number(value))) {
            setIsValidNif(true);
            return true;
        } else if (value.length === 0) {
            setIsValidNif(null);
            return null;
        } else {
            setIsValidNif(false);
            return false;
        }
    };

    const handleNifChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newValue = e.target.value;
        setNif(newValue);
        validateNif(newValue);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const commonData = {
                room,
                reservationNumber,
                nif,
                producerName,
                email,
                contact,
                responsablePerson,
                event,
                eventClassification,
                author, // Use the author state directly
                isActive: true // Set isActive to true by default
            };

            const promises = dateEntries.map(entry => {
                const reservationData = {
                    ...commonData,
                    date: entry.date,
                    type: entry.type,
                    notes: entry.notes
                };
                return createReservation(reservationData);
            });

            const results = await Promise.all(promises);
            const allSuccess = results.every(success => success);

            if (allSuccess) {
                alert(translations.reservationSuccess);
                navigate('/calendar');
            } else {
                alert(translations.reservationError);
            }
        } catch (error) {
            console.error('Failed to submit reservation:', error);
            alert(translations.reservationError);
        }
    };

    const handleReturn = () => {
        navigate('/calendar');
    };

    const isPastDate = (date: Date) => {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        return date < today;
    };

    const handleDateSelection = (selectedDate: Date) => {
        if (isPastDate(selectedDate)) {
            return;
        }

        // Check if a date entry already exists for the selected date
        const dateExists = dateEntries.some(entry => entry.date.toDateString() === selectedDate.toDateString());
        if (!dateExists) {
            // Create a new date entry
            const newEntry: DateEntry = {
                date: selectedDate,
                type: 'event',
                event: '',
                hasNotes: false,
                notes: ''
            };
            setDateEntries([...dateEntries, newEntry]);
        }

        setDate(selectedDate);
    };

    const handleRemoveEntry = (index: number) => {
        const newEntries = dateEntries.filter((_, i) => i !== index);
        setDateEntries(newEntries);
    };

    const handleTypeChange = (index: number, value: string) => {
        const newEntries = [...dateEntries];
        newEntries[index].type = value;
        setDateEntries(newEntries);
    };

    const handleEventChange = (index: number, value: string) => {
        const newEntries = [...dateEntries];
        newEntries[index].event = value;
        setDateEntries(newEntries);
    };

    const handleNotesToggle = (index: number) => {
        const newEntries = [...dateEntries];
        newEntries[index].hasNotes = !newEntries[index].hasNotes;
        setDateEntries(newEntries);
    };

    const handleNotesChange = (index: number, value: string) => {
        const newEntries = [...dateEntries];
        newEntries[index].notes = value;
        setDateEntries(newEntries);
    };

    // Add effect to update all date entries when event changes
    useEffect(() => {
        if (dateEntries.length > 0) {
            const updatedEntries = dateEntries.map(entry => ({
                ...entry,
                event: event // Sync the main event field with all entries
            }));
            setDateEntries(updatedEntries);
        }
    }, [event]); // Update whenever event changes

    const isFormValid = (): boolean => {
        // Check if all required fields are filled
        const requiredFields = {
            reservationNumber,
            nif,
            producerName,
            email,
            contact,
            responsablePerson,
            event,
            eventClassification,
            date,
            type,
            author // Include author in validation
        };

        // Log each field's value for debugging
        console.log('Form validation:', requiredFields);

        // Check if any field is empty or only whitespace
        const areMainFieldsFilled = Object.values(requiredFields)
            .every(field => field && field.toString().trim() !== '');
        
        const isNifValid = isValidNif === true;
        
        const hasValidDateEntries = dateEntries.length > 0 && 
            dateEntries.every(entry => entry.type && entry.type.trim() !== '');

        // Log validation results
        console.log('Fields filled:', areMainFieldsFilled);
        console.log('NIF valid:', isNifValid);
        console.log('Date entries valid:', hasValidDateEntries);
        console.log('Date entries:', dateEntries);

        const isValid = areMainFieldsFilled && isNifValid && hasValidDateEntries;
        console.log('Form is valid:', isValid);

        return isValid;
    };

    return (
        <form className="new-reservation-form" onSubmit={handleSubmit}>
            <div className="form-group">
                <label>{translations.room}:</label>
                <input type="text" value={room} readOnly />
            </div>
            <div className="form-group">
                <label>{translations.reservationNumber}:</label>
                <input 
                    type="text" 
                    value={reservationNumber} 
                    onChange={(e) => setReservationNumber(e.target.value)} 
                />
            </div>
            <div className="form-group">
                <label>{translations.nif}:</label>
                <input 
                    type="text"
                    maxLength={9}
                    value={nif}
                    onChange={handleNifChange}
                    className={isValidNif === true ? 'valid' : isValidNif === false ? 'invalid' : ''}
                />
            </div>
            <div className="form-group">
                <label>{translations.producerName}:</label>
                <input 
                    type="text" 
                    value={producerName} 
                    onChange={(e) => setProducerName(e.target.value)} 
                />
            </div>
            <div className="form-group">
                <label>{translations.email}:</label>
                <input 
                    type="email" 
                    value={email} 
                    onChange={(e) => setEmail(e.target.value)} 
                />
            </div>
            <div className="form-group">
                <label>{translations.contact}:</label>
                <input 
                    type="text" 
                    value={contact} 
                    onChange={(e) => setContact(e.target.value)} 
                />
            </div>
            <div className="form-group">
                <label>{translations.responsablePerson}:</label>
                <input 
                    type="text" 
                    value={responsablePerson} 
                    onChange={(e) => setResponsablePerson(e.target.value)} 
                />
            </div>
            <div className="form-group">
                <label>{translations.event}:</label>
                <input 
                    type="text" 
                    value={event} 
                    onChange={(e) => setEvent(e.target.value)} 
                />
            </div>
            <div className="form-group">
                <label>{translations.eventClassification}:</label>
                <select 
                    value={eventClassification} 
                    onChange={(e) => setEventClassification(e.target.value)}
                >
                    <option value="">{translations.selectClassification}</option>
                    <option value="allAges">{translations.allAges}</option>
                    {/* Add more options here if needed */}
                </select>
            </div>
            <div className="form-group datepicker-group">
                <label>{translations.scheduledDays}:</label>
                <DatePicker
                    selected={date}
                    onChange={handleDateSelection}
                    inline
                    dateFormat="dd/MM/yyyy"
                    className="date-picker"
                    calendarClassName="mini-calendar"
                    locale={locale === 'pt' ? pt : enUS}
                    minDate={new Date()} // Prevent selecting past dates
                />
            </div>
            <div className="date-entries">
                {dateEntries.map((entry, index) => (
                    <div key={index} className="date-entry">
                        <div className="date-entry-header">
                            <span>{entry.date.toLocaleDateString(locale, { 
                                day: '2-digit',
                                month: 'short',
                                year: 'numeric'
                            })}</span>
                            <select
                                value={entry.type}
                                onChange={(e) => handleTypeChange(index, e.target.value)}
                            >
                                <option value="">{translations.selectType}</option>
                                <option value="event">{translations.event}</option>
                                <option value="assembly">{translations.assembly}</option>
                                <option value="disassembly">{translations.disassembly}</option>
                                <option value="others">{translations.others}</option>
                            </select>
                            <div className="placeholder-display">
                                {event}
                            </div>
                            <label className="notes-checkbox">
                                <input
                                    type="checkbox"
                                    checked={entry.hasNotes}
                                    onChange={() => handleNotesToggle(index)}
                                />
                                <span>{translations.notes}</span>
                            </label>
                        </div>
                        {entry.hasNotes && (
                            <textarea
                                value={entry.notes}
                                onChange={(e) => handleNotesChange(index, e.target.value)}
                                className="notes-textarea"
                                placeholder={translations.placeholder}
                                rows={6}
                            />
                        )}
                        <button
                            type="button"
                            className="remove-entry-button"
                            onClick={() => handleRemoveEntry(index)}
                        >
                            Remove
                        </button>
                    </div>
                ))}
            </div>
            <div className="form-buttons">
                <button 
                    type="submit" 
                    className="submit-button"
                    disabled={!isFormValid()}
                >
                    {translations.submit}
                </button>
                <button 
                    type="button" 
                    onClick={handleReturn} 
                    className="return-button"
                >
                    {translations.return}
                </button>
            </div>
        </form>
    );
};

export default NewReservation;

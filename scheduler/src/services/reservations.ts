import axios from 'axios';

interface Reservation {
    room: string;
    reservationNumber: string;
    nif: string;
    producerName: string;
    email: string;
    contact: string;
    responsablePerson: string;
    event: string;
    eventClassification: string;
    date: Date;
    type: string;
    notes?: string;
    isActive: boolean;
    author: string;
}

export const createReservation = async (reservation: Reservation): Promise<boolean> => {
    try {
        const token = localStorage.getItem('token'); // Retrieve the token from local storage
        const response = await axios.post('http://localhost:5000/api/reservations', reservation, {
            headers: {
                'Authorization': `Bearer ${token}` // Include the token in the request headers
            }
        });
        return response.status === 201;
    } catch (error) {
        console.error('Failed to create reservation:', error);
        throw error;
    }
};

export const fetchReservations = async (start: string, end: string): Promise<Reservation[]> => {
    console.log(`Fetching reservations from ${start} to ${end}`);
    try {
        const token = localStorage.getItem('token'); // Retrieve the token from local storage
        const response = await axios.get(`http://localhost:5000/api/reservations?start=${start}&end=${end}`, {
            headers: {
                'Authorization': `Bearer ${token}` // Include the token in the request headers
            }
        });
        console.log('Reservations fetched successfully:', response.data);
        return response.data;
    } catch (error) {
        console.error('Failed to fetch reservations:', error);
        throw error;
    }
};

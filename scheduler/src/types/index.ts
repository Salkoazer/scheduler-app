export interface User {
    id: string;
    username: string;
    password: string; // Note: In a real application, do not store passwords in plain text
}

export interface Show {
    id: string;
    date: string; // ISO format date
    title: string;
    description: string;
    time: string; // Time of the show
}

export interface Reservation {
    _id?: string;
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
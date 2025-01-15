import mongoose from 'mongoose';

const ReservationSchema = new mongoose.Schema({
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    room: { type: String, required: true },
    reservationNumber: { type: String, required: true },
    nif: { type: String, required: true },
    producerName: { type: String, required: true },
    email: { type: String, required: true },
    contact: { type: String, required: true },
    responsablePerson: { type: String, required: true },
    event: { type: String, required: true },
    eventClassification: { type: String, required: true },
    date: { type: Date, required: true },
    type: { type: String, required: true },
    notes: { type: String, required: false },
    isActive: { type: Boolean, default: true },
    author: { type: String, required: true }
});

const Reservation = mongoose.model('Reservation', ReservationSchema);

export default Reservation;

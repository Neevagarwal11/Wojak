"use client";

import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import './styles.css';
import Login from "../components/login";

type Event = {
  id: number;
  name: string;
  date: string;
  location: string;
};

const events = [
  { id: 1, name: "Concert A", date: "2023-12-01", location: "Venue A" },
  { id: 2, name: "Concert B", date: "2023-12-05", location: "Venue B" },
];

export default function Home() {
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [showLogin, setShowLogin] = useState(false);

  return (
    <div className="w-full flex flex-col gap-5 relative border-2 items-center justify-center">
      
      <div className="border-2 rounded-xl p-2 absolute top-5 right-10">
      <button onClick={() => setShowLogin(!showLogin)} className="font-black">
        {showLogin ? "Hide Login" : "Login"}
      </button>
        {showLogin && <Login />}
      </div>


    <div className="container w-[60%]">
      <h1>Event Listing</h1>
      <ul className="event-list">
        {events.map((event) => (
          <li key={event.id} className="event-item">
            <h2 className="font-black">{event.name}</h2>
            <p className="font-black">Date: {event.date}</p>
            <p className="font-black">Location: {event.location}</p>
            <button onClick={() => setSelectedEvent(event)} className="font-black">Book Now</button>
          </li>
        ))}
      </ul>

      {selectedEvent && (
        <div className="ticket">
          <h2>Booking Confirmation</h2>
          <div className="ticket-details">
            <p><strong>Event:</strong> {selectedEvent.name}</p>
            <p><strong>Date:</strong> {selectedEvent.date}</p>
            <p><strong>Location:</strong> {selectedEvent.location}</p>
          </div>
          <div className="qr-code">
            <QRCodeSVG value={`Event: ${selectedEvent.name}, Date: ${selectedEvent.date}, Location: ${selectedEvent.location}`} />
          </div>
        </div>
      )}
    </div>
  </div>
  );
}
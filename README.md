# Football Match Organizer
## Overview
Football Match Organizer is a web application designed to facilitate the organization of football matches for pitch owners and to connect players with available slots. The application allows users to register, book slots for matches, manage their bookings, and provides administrators with tools to manage slots and user accounts.

## Features
1. User Registration and Authentication:
 - Users can register for an account with a unique username, email, and phone number (mail validation, too).
 - Passwords are securely hashed using Werkzeug's password hashing utilities.
 - Account confirmation via email with unique tokens for verification.
 - Login functionality with error handling for invalid credentials.
2. Slot Management:
 - Pitch owners (gestori) can add new slots specifying the date, time, and available spots.
 - Slots are displayed with available spots on the user interface.
 - Pitch owners can delete existing slots.
3. Slot Booking:
 - Registered users can view available slots and book spots for matches.
 - Users can cancel their bookings if needed, and the available spots are updated accordingly.
 - Error handling for booking slots with insufficient available spots.
4. Referral System:
 - Users are provided with a referral code upon registration.
 - Referral bonuses are calculated for users based on the number of referrals who make bookings.
 - Referral codes are stored securely in the database.
5. Profile Management:
 - Users can view their profile information, including booked slots and referral bonuses.
 - Bonus points are updated in real-time based on successful referrals.


## Technologies Used
Flask: The web framework used for backend development.
Flask SQLAlchemy: For interacting with the SQLite database.
Flask Login: Provides user session management and authentication.
Flask WTF: Used for form validation and CSRF protection.
Flask Mail: Facilitates sending confirmation emails to users.
Werkzeug: Used for password hashing and security features.
SQLite: The relational database management system used for data storage.
JavaScript (AJAX): Asynchronous requests for retrieving and updating available slots dynamically.
HTML/CSS: For frontend design and layout.
Jinja2: Template engine for rendering dynamic content in Flask.

# README.md for the Scheduler Project

# Scheduler

Scheduler is a simple web application designed for theater companies to manage and schedule their shows. The application features a login screen and a calendar interface that allows users to select dates and schedule shows.

## Features

- User authentication with a login form
- Calendar view for selecting dates
- Scheduling shows for selected dates

## Project Structure

```
scheduler
├── src
│   ├── components
│   │   ├── Login.tsx
│   │   ├── Calendar.tsx
│   │   └── Schedule.tsx
│   ├── services
│   │   ├── auth.ts
│   │   └── api.ts
│   ├── types
│   │   └── index.ts
│   ├── App.tsx
│   └── index.tsx
├── public
│   └── index.html
├── package.json
├── tsconfig.json
└── README.md
```

## Getting Started

1. Clone the repository:
   ```
   git clone <repository-url>
   cd scheduler
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the development server:
   ```
   npm start
   ```

4. Open your browser and navigate to `http://localhost:3000` to view the application.

## Usage

- Log in using the provided credentials.
- Use the calendar to select a date and schedule a show.

## License

This project is licensed under the MIT License.
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1e3c72,100:2a5298&height=200&section=header&text=SportLog&fontSize=70&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=SRM%20Student%20Achievement%20Portal&descAlignY=55&descSize=18" width="100%"/>

<a href="YOUR-VERCEL-DOMAIN.vercel.app">
  <img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&size=22&pause=1500&color=2A5298&center=true&vCenter=true&width=500&lines=Live+Demo+%E2%86%92+sportslog-1.onrender.com;Track+Achievements.+Celebrate+Athletes." alt="Typing SVG" />
</a>

<br/>

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=for-the-badge&logo=express&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=jsonwebtokens&logoColor=white)

</div>

<br/>

## Overview

**SportLog** lets SRMIST students sign up, log in, and record their sports achievements — medals, events, scores, and rankings. It surfaces a live stats dashboard so anyone can see top athletes, medal counts, and participation across different sports.

> The live demo runs on Render's free tier — it may take 30–60 seconds to wake up after inactivity, and stored data may periodically reset since the free tier has no persistent disk.

<br/>

## Tech Stack

<div align="center">

| Layer        | Tech                                                        |
|--------------|--------------------------------------------------------------|
| Backend      | Node.js, Express, `better-sqlite3`, JWT auth, `bcryptjs`      |
| Frontend     | Single-file HTML/CSS/JS (`public/index.html`) — no build step |
| Database     | SQLite — auto-created on first run, zero setup               |
| Hosting      | [Render](https://render.com) (free-tier Web Service)          |

</div>

<br/>

## Project Structure

```
sportslog/
├── server.js              # Express API + Vercel entrypoint
├── package.json
├── package-lock.json
├── vercel.json
└── public/
    └── index.html          # Frontend — HTML/CSS/JS in one file
```

<br/>

## Getting Started

**Prerequisites:** [Node.js](https://nodejs.org/) v16+

```bash
# Clone the repo
git clone https://github.com/SREEJITH-16/sportslog.git
cd sportslog

# Install dependencies
npm install

# Start the server
npm start          # or: npm run dev  (auto-restarts on changes)
```

Then open **http://localhost:3000** — that's the whole app, frontend and backend served from one place. The SQLite file (`sportlog.db`) and seed data (10 sports) are created automatically on first launch.

<br/>

## Configuration

| Variable     | Default                          | Purpose                         |
|--------------|-----------------------------------|-----------------------------------|
| `PORT`       | `3000`                            | Port the server listens on       |
| `JWT_SECRET` | `sportlog_secret_change_in_prod`  | Secret used to sign auth tokens  |

```bash
PORT=4000 JWT_SECRET=your-long-random-string npm start
```

> Always set a strong `JWT_SECRET` for any real or shared deployment — never rely on the default.

<br/>

## Account Rules

- Registration requires a 15-character registration number + a `@srmist.edu.in` email
- Passwords must be 8+ characters

<br/>

## API Reference

<details>
<summary><strong>Click to expand full endpoint list</strong></summary>

<br/>

All endpoints are prefixed with `/api`. Authenticated routes need `Authorization: Bearer <token>`.

| Method   | Endpoint                          | Auth Required | Description                                  |
|----------|-------------------------------------|:----:|------------------------------------------------|
| `POST`   | `/api/auth/signup`                 | No   | Create a student account                        |
| `POST`   | `/api/auth/login`                  | No   | Log in, returns a JWT                            |
| `GET`    | `/api/auth/me`                     | Yes  | Get the logged-in user's profile                |
| `GET`    | `/api/sports`                      | No   | List all sports                                  |
| `GET`    | `/api/achievements`                | No   | List achievements (filterable)                   |
| `POST`   | `/api/achievements`                | Yes  | Log a new achievement                            |
| `DELETE` | `/api/achievements/:id`            | Yes  | Delete an achievement                            |
| `GET`    | `/api/stats`                       | No   | Dashboard stats — top students, medals, etc.     |
| `GET`    | `/api/events?location=`            | No   | List events, optionally filtered by location      |
| `GET`    | `/api/students/:id/achievements`   | No   | All achievements for one student                 |

</details>

<br/>

## Deployment

The live demo is deployed on **Render** as a free Web Service:

| Setting          | Value                        |
|-------------------|-------------------------------|
| Root Directory     | `backend`                    |
| Build Command       | `npm install`                 |
| Start Command        | `npm start`                   |
| Env Variable          | `JWT_SECRET` (random string) |

> Render's free tier doesn't persist the filesystem across restarts, so `sportlog.db` resets periodically. For durable storage, add Render's paid Persistent Disk, or migrate to a hosted DB like Postgres or Turso.


<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2a5298,100:1e3c72&height=100&section=footer" width="100%"/>

# learn-cicd-starter (Notely)

![CI](https://github.com/Lunnaris01/learn-cicd-starter/actions/workflows/ci.yml/badge.svg)
![CD](https://github.com/Lunnaris01/learn-cicd-starter/actions/workflows/cd.yml/badge.svg)


This repo contains my Solution for the "Notely" application exercises for the "Learn CICD" course on [Boot.dev](https://boot.dev).

## Local Development

Make sure you're on Go version 1.22+.

Create a `.env` file in the root of the project with the following contents:

```bash
PORT="8080"
```

Run the server:

```bash
go build -o notely && ./notely
```

*This starts the server in non-database mode.* It will serve a simple webpage at `http://localhost:8080`.

You do *not* need to set up a database or any interactivity on the webpage yet. Instructions for that will come later in the course!

Lunnaris01's version of Boot.dev's Notely app.

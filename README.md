# express-passport-facebook-example

### Set up posgres

1. heroku addons:create heroku-postgresql:hobby-dev
2. heroku config
3. Copy the POSTGRES_URL to .env file
4. Connect to db and import the users table in db.sql file

### Run

1. npm install
2. node index.js

### Deploy on heroku

1. git init
2. heroku login
3. heroku create
4. git push heroku master

CREATE TABLE users (
	id serial,
	username text DEFAULT null,
	email text DEFAULT null,
	passwd_hash text DEFAULT null,
	fbid text DEFAULT null,
	fbtoken text DEFAULT null,
	createdAt timestamp DEFAULT null,
	updatedAt timestamp DEFAULT null
)
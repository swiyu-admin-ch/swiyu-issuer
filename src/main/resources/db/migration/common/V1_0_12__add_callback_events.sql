CREATE TABLE callback_event (
    id uuid NOT NULL,
    subjectId uuid NOT NULL,
    event text NOT NULL,
    type text NOT NULL,
    timestamp TIMESTAMP NOT NULL
);

ALTER TABLE callback_event ADD CONSTRAINT callback_event_pkey PRIMARY KEY (id);
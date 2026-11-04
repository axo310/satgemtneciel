CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  approved BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_lower ON users (lower(username));

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE companies (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  activity TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  website TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'attente',
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO companies (name, address, activity, phone, website, note, status) VALUES
('Sogetrel – Toulouse','105 rue Edmond Rostand, 31200 Toulouse','Infrastructures numériques, réseaux télécoms et fibre optique','01 41 17 42 42','https://sogetrel.fr','Pertinent pour la partie réseaux/fibre de CIEL','attente'),
('A.I.D – Dépannage informatique','30 boulevard Silvio Trentin, 31200 Toulouse','Dépannage et assistance informatique','07 67 21 67 23','','Piste pour maintenance et diagnostic PC','attente'),
('SPIE ICS – Service Desk','6 rue Jules Védrines, 31400 Toulouse','Support informatique, systèmes et services numériques','05 34 61 84 00','https://spie-ics.com','Découverte du support IT et des systèmes','attente'),
('Capgemini Takeoff','11 avenue Didier Daurat, 31700 Blagnac','Ingénierie et projets numériques / informatiques','05 34 61 04 00','https://capgemini.com','Piste pour découvrir l’informatique en entreprise','attente'),
('Beltran Informatique SARL','69 route de Grenade, 31700 Blagnac','Dépannage, maintenance informatique et installation d’équipements réseau','05 61 49 29 74','','Entreprise informatique locale ; dépannage et réseaux','attente'),
('Orange – boutique Fenouillet','Espace Fenouillet, 19 rue des Usines, 31150 Fenouillet','Télécommunications, box, fibre et téléphonie (activité boutique)','','https://orange.fr','Téléphone à demander en boutique. Très proche et lié aux télécoms ; demander s’il existe une équipe technique locale pouvant accueillir un stagiaire','relance'),
('SFR – boutique Fenouillet','Espace Fenouillet, 19 rue des Usines, 31150 Fenouillet','Télécommunications et équipements mobiles (activité boutique)','05 67 16 74 17','https://sfr.fr','Proche et lié aux télécoms (attente de réponse)','relance'),
('Cybertek Toulouse Nord','83 route de Paris, 31150 Fenouillet','','','','','refus');

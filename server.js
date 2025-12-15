// ===== SERVER.JS FINAL ET COMPLET (AVEC DISCUSSIONS) =====
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;


const JWT_SECRET = process.env.JWT_SECRET;
const CHEF_SECURITY_CODE = process.env.CHEF_SECURITY_CODE;


// Middleware
app.use(cors());
app.use(express.json());

// Initialisation de la base de données SQLite
const path = require('path');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'polytechnique.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error('Erreur SQLite:', err);
  else initDatabase();
});


// Création des tables
function initDatabase() {
  db.serialize(() => {
    // Table des utilisateurs
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        prenom TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL, 
        statut TEXT NOT NULL CHECK(statut IN ('etudiant', 'enseignant', 'chef_departement')),
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tables filières
    db.run(`
      CREATE TABLE IF NOT EXISTS filieres (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Tables bureaux
    db.run(`
      CREATE TABLE IF NOT EXISTS bureaux (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Tables salles - MODIFIÉE avec nom UNIQUE et contrainte exclusive
    db.run(`
      CREATE TABLE IF NOT EXISTS salles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL UNIQUE,
        capacite INTEGER NOT NULL,
        batiment TEXT NOT NULL,
        description TEXT,
        filiere_id INTEGER,
        bureau_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (filiere_id) REFERENCES filieres(id) ON DELETE SET NULL,
        FOREIGN KEY (bureau_id) REFERENCES bureaux(id) ON DELETE SET NULL,
        CHECK (
          (filiere_id IS NOT NULL AND bureau_id IS NULL) OR 
          (filiere_id IS NULL AND bureau_id IS NOT NULL)
        )
      )
    `);

    // NOUVELLE TABLE: Discussions
    db.run(`
      CREATE TABLE IF NOT EXISTS discussions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        read_status BOOLEAN DEFAULT 0,
        sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `, (err) => {
      if (err) {
        console.error('Erreur lors de la création de la table discussions:', err);
      } else {
        console.log('✓ Table discussions créée avec succès');
        // Ajouter la colonne description si elle n'existe pas (pour mise à jour)
        db.run(`ALTER TABLE salles ADD COLUMN description TEXT`, (err) => {
          if (err && !err.message.includes('duplicate column')) {
            console.error('Note: Colonne description peut déjà exister');
          }
        });
      }
    });
  });
}

// ===================================
// MIDDLEWARES DE PROTECTION
// ===================================

function protect(req, res, next) {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    if (!token) {
        return res.status(401).json({ error: 'Accès refusé. Token manquant.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; 
        next();
    } catch (err) {
        res.status(403).json({ error: 'Token invalide ou expiré.' });
    }
}

function restrictTo(statut) {
    return (req, res, next) => {
        if (req.user.statut !== statut) {
            return res.status(403).json({ error: `Opération non autorisée. Seul un ${statut} peut effectuer cette action.` });
        }
        next();
    };
}

// ===================================
// ROUTES AUTHENTIFICATION
// ===================================

// Inscription
app.post('/api/auth/register', async (req, res) => {
  const { nom, prenom, email, statut, password, securityCode } = req.body; 

  if (!nom || !prenom || !email || !statut || !password) {
    return res.status(400).json({ error: 'Tous les champs sont requis' });
  }

  if (!['etudiant', 'enseignant', 'chef_departement'].includes(statut)) {
    return res.status(400).json({ error: 'Statut invalide' });
  }
  if (statut === 'chef_departement' && securityCode !== CHEF_SECURITY_CODE) {
    return res.status(403).json({ error: 'Code de sécurité invalide pour chef de département' });
  }

  try {
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      if (user) {
        return res.status(400).json({ error: 'Un compte avec cette adresse email existe déjà' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        'INSERT INTO users (nom, prenom, email, statut, password) VALUES (?, ?, ?, ?, ?)',
        [nom, prenom, email, statut, hashedPassword],
        function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          res.status(201).json({ 
            message: 'Inscription réussie',
            user: { id: this.lastID, nom, prenom, email, statut }
          });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Connexion
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body; 

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => { 
    if (err) return res.status(500).json({ error: err.message });

    if (!user) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    try {
      const validPassword = await bcrypt.compare(password, user.password);
      
      if (!validPassword) {
        return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
      }

      const token = jwt.sign(
        { id: user.id, nom: user.nom, email: user.email, statut: user.statut },
        JWT_SECRET,
        { expiresIn: '1d' } 
      );

      res.json({
        message: 'Connexion réussie',
        token: token, 
        user: {
          id: user.id,
          nom: user.nom,
          prenom: user.prenom,
          email: user.email,
          statut: user.statut
        }
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
});

// ===================================
// ROUTES UTILISATEURS
// ===================================

app.get('/api/users/chef-departement', protect, (req, res) => {
    // Sélectionne uniquement les informations nécessaires pour l'affichage (pas le mot de passe)
    const query = `
        SELECT id, nom, prenom, email, statut, created_at
        FROM users 
        WHERE statut = 'chef_departement'
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// ===================================
// ROUTES DISCUSSIONS
// ===================================

const discussionsRouter = express.Router();
app.use('/api/discussions', protect, discussionsRouter);

// POST: Envoyer un message
discussionsRouter.post('/send', (req, res) => {
    const { receiverId, message } = req.body;
    const senderId = req.user.id;
    const senderStatut = req.user.statut;

    if (!receiverId || !message) {
        return res.status(400).json({ error: 'ID du destinataire et message sont requis.' });
    }

    // Vérifier le destinataire
    db.get('SELECT statut FROM users WHERE id = ?', [receiverId], (err, receiver) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!receiver) {
            return res.status(404).json({ error: 'Destinataire introuvable.' });
        }

        // ❌ Chef → Chef interdit
        if (
            senderStatut === 'chef_departement' &&
            receiver.statut === 'chef_departement'
        ) {
            return res.status(403).json({
                error: 'Les chefs de département ne peuvent pas communiquer entre eux.'
            });
        }

        // ❌ Utilisateur → Utilisateur interdit
        if (
            senderStatut !== 'chef_departement' &&
            receiver.statut !== 'chef_departement'
        ) {
            return res.status(403).json({
                error: 'Les utilisateurs ne peuvent pas communiquer entre eux.'
            });
        }

        // ✅ Cas autorisés : Chef ↔ Utilisateur
        db.run(
            'INSERT INTO discussions (sender_id, receiver_id, message) VALUES (?, ?, ?)',
            [senderId, receiverId, message],
            function (err) {
                if (err) return res.status(500).json({ error: err.message });
                res.status(201).json({
                    message: 'Message envoyé',
                    discussionId: this.lastID,
                    sent_at: new Date().toISOString()
                });
            }
        );
    });
});


// GET: Récupérer tous les messages d'une discussion donnée (entre l'utilisateur actuel et un partenaire)
discussionsRouter.get('/:partnerId', async (req, res) => {
    const currentUserId = req.user.id;
    const partnerId = req.params.partnerId;

    // Récupère les messages où l'utilisateur actuel est l'expéditeur OU le destinataire, 
    // et où le partenaire est l'autre partie.
    const query = `
        SELECT 
            d.id, d.sender_id, d.receiver_id, d.message, d.read_status, d.sent_at,
            s.nom AS sender_nom, s.prenom AS sender_prenom, s.statut AS sender_statut,
            r.nom AS receiver_nom, r.prenom AS receiver_prenom, r.statut AS receiver_statut
        FROM discussions d
        JOIN users s ON d.sender_id = s.id
        JOIN users r ON d.receiver_id = r.id
        WHERE 
            (d.sender_id = ? AND d.receiver_id = ?) OR 
            (d.sender_id = ? AND d.receiver_id = ?)
        ORDER BY d.sent_at ASC
    `;

    db.all(query, [currentUserId, partnerId, partnerId, currentUserId], (err, messages) => {
        if (err) return res.status(500).json({ error: err.message });
        
        // OPTIONNEL: Marquer les messages entrants comme lus
        // Note: l'UPDATE est asynchrone mais ne bloque pas la réponse
        db.run('UPDATE discussions SET read_status = 1 WHERE receiver_id = ? AND sender_id = ? AND read_status = 0', [currentUserId, partnerId]);

        res.json(messages);
    });
});

// GET: Récupérer la liste des conversations de l'utilisateur actuel (Sidebar des discussions)
discussionsRouter.get('/', async (req, res) => {
    const currentUserId = req.user.id;
    const currentUserStatut = req.user.statut;
    
    // Sous-requête pour obtenir tous les IDs de partenaires de conversation uniques
    const partnerIdsQuery = `
        SELECT DISTINCT CASE 
            WHEN sender_id = ? THEN receiver_id 
            ELSE sender_id 
        END AS partner_id
        FROM discussions
        WHERE sender_id = ? OR receiver_id = ?
    `;

    db.all(partnerIdsQuery, [currentUserId, currentUserId, currentUserId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });

        const partnerIds = rows.map(row => row.partner_id).filter(id => id !== currentUserId);

        if (partnerIds.length === 0) {
            return res.json([]);
        }

        // Récupérer les infos des partenaires
        const placeholders = partnerIds.map(() => '?').join(',');
        
        let selectUsersQuery = `
            SELECT id, nom, prenom, statut
            FROM users
            WHERE id IN (${placeholders})
        `;

        if (currentUserStatut !== 'chef_departement') {
            // Si l'utilisateur n'est pas chef, il ne devrait voir que les chefs.
            selectUsersQuery += ` AND statut = 'chef_departement'`;
        } else {
            // Si l'utilisateur est chef, il ne devrait voir que les non-chefs (pour respecter la règle Chef -> Chef)
            selectUsersQuery += ` AND statut != 'chef_departement'`;
        }

        db.all(selectUsersQuery, partnerIds, (err, partners) => {
            if (err) return res.status(500).json({ error: err.message });

            const conversationPromises = partners.map(partner => {
                return new Promise((resolve, reject) => {
                    // 1. Récupérer le dernier message
                    db.get(`
                        SELECT message, sent_at
                        FROM discussions
                        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                        ORDER BY sent_at DESC
                        LIMIT 1
                    `, [currentUserId, partner.id, partner.id, currentUserId], (err, lastMessage) => {
                        if (err) return reject(err);

                        // 2. Compter les messages non lus envoyés par le partenaire
                        db.get(`
                            SELECT COUNT(id) as unreadCount
                            FROM discussions
                            WHERE sender_id = ? AND receiver_id = ? AND read_status = 0
                        `, [partner.id, currentUserId], (err, unreadCount) => {
                            if (err) return reject(err);

                            resolve({
                                ...partner,
                                lastMessage: lastMessage?.message,
                                lastMessageSentAt: lastMessage?.sent_at,
                                unreadCount: unreadCount.unreadCount
                            });
                        });
                    });
                });
            });

            Promise.all(conversationPromises)
                .then(conversations => res.json(conversations))
                .catch(err => res.status(500).json({ error: err.message }));
        });
    });
});


// ===================================
// CONFIGURATION DES ROUTES DE RESSOURCES (EXISTANTES)
// ===================================

const sallesRouter = express.Router();
const filieresRouter = express.Router();
const bureauxRouter = express.Router();

app.use('/api/salles', protect, sallesRouter);
app.use('/api/filieres', protect, filieresRouter);
app.use('/api/bureaux', protect, bureauxRouter);

// --- ROUTES SALLES (CRUD) ---
sallesRouter.get('/', (req, res) => {
    const query = `
        SELECT 
            s.id, s.nom, s.capacite, s.batiment, s.description, s.filiere_id, s.bureau_id,
            f.nom AS filiere_nom, b.nom AS bureau_nom
        FROM salles s
        LEFT JOIN filieres f ON s.filiere_id = f.id
        LEFT JOIN bureaux b ON s.bureau_id = b.id
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

sallesRouter.post('/', restrictTo('chef_departement'), (req, res) => {
    const { nom, capacite, batiment, description, filiere_id, bureau_id } = req.body;
    
    if (!nom || !capacite || !batiment) {
        return res.status(400).json({ error: 'Nom, capacité et bâtiment sont requis.' });
    }
    
    if ((filiere_id && bureau_id) || (!filiere_id && !bureau_id)) {
        return res.status(400).json({ 
            error: 'Une salle doit être assignée soit à une filière, soit à un bureau (mais pas les deux).' 
        });
    }

    // ❗ Vérification du nom unique
    db.get('SELECT id FROM salles WHERE nom = ?', [nom], (err, existingNom) => {
        if (err) return res.status(500).json({ error: err.message });
        if (existingNom) {
            return res.status(409).json({ error: 'Une salle avec ce nom existe déjà.' });
        }

        // ❗ Vérification unique par filière ou bureau
        const checkQuery = filiere_id 
            ? 'SELECT id FROM salles WHERE filiere_id = ?' 
            : 'SELECT id FROM salles WHERE bureau_id = ?';
        const checkValue = filiere_id || bureau_id;

        db.get(checkQuery, [checkValue], (err, existingSalle) => {
            if (err) return res.status(500).json({ error: err.message });
            if (existingSalle) {
                return res.status(409).json({ 
                    error: filiere_id 
                        ? 'Cette filière a déjà une salle assignée.' 
                        : 'Ce bureau a déjà une salle assignée.' 
                });
            }

            db.run(
                'INSERT INTO salles (nom, capacite, batiment, description, filiere_id, bureau_id) VALUES (?, ?, ?, ?, ?, ?)',
                [nom, capacite, batiment, description || null, filiere_id || null, bureau_id || null],
                function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE constraint failed: salles.nom')) {
                            return res.status(409).json({ error: 'Une salle avec ce nom existe déjà.' });
                        }
                        return res.status(500).json({ error: err.message });
                    }
                    res.status(201).json({ id: this.lastID, nom, capacite, batiment, description });
                }
            );
        });
    });
});

sallesRouter.put('/:id', restrictTo('chef_departement'), (req, res) => {
    const { nom, capacite, batiment, description, filiere_id, bureau_id } = req.body;
    const { id } = req.params;
    
    if ((filiere_id && bureau_id) || (!filiere_id && !bureau_id)) {
        return res.status(400).json({ 
            error: 'Une salle doit être assignée soit à une filière, soit à un bureau (mais pas les deux).' 
        });
    }

    // ❗ Vérification du nom unique (sauf pour la salle actuelle)
    db.get('SELECT id FROM salles WHERE nom = ? AND id != ?', [nom, id], (err, existingNom) => {
        if (err) return res.status(500).json({ error: err.message });
        if (existingNom) {
            return res.status(409).json({ error: 'Une salle avec ce nom existe déjà.' });
        }

        // ❗ Vérification unique par filière ou bureau (sauf pour la salle actuelle)
        const checkQuery = filiere_id 
            ? 'SELECT id FROM salles WHERE filiere_id = ? AND id != ?' 
            : 'SELECT id FROM salles WHERE bureau_id = ? AND id != ?';
        const checkValues = filiere_id ? [filiere_id, id] : [bureau_id, id];

        db.get(checkQuery, checkValues, (err, existingSalle) => {
            if (err) return res.status(500).json({ error: err.message });
            if (existingSalle) {
                return res.status(409).json({ 
                    error: filiere_id 
                        ? 'Cette filière a déjà une salle assignée.' 
                        : 'Ce bureau a déjà une salle assignée.' 
                });
            }

            db.run(
                'UPDATE salles SET nom = ?, capacite = ?, batiment = ?, description = ?, filiere_id = ?, bureau_id = ? WHERE id = ?',
                [nom, capacite, batiment, description || null, filiere_id || null, bureau_id || null, id],
                function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE constraint failed: salles.nom')) {
                            return res.status(409).json({ error: 'Une salle avec ce nom existe déjà.' });
                        }
                        return res.status(500).json({ error: err.message });
                    }
                    if (this.changes === 0) return res.status(404).json({ error: 'Salle non trouvée.' });
                    res.json({ message: 'Salle mise à jour avec succès.' });
                }
            );
        });
    });
});


sallesRouter.delete('/:id', restrictTo('chef_departement'), (req, res) => {
    db.run('DELETE FROM salles WHERE id = ?', req.params.id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Salle non trouvée.' });
        res.json({ message: 'Salle supprimée avec succès.' });
    });
});

// --- ROUTES FILIÈRES (CRUD) ---
filieresRouter.get('/', (req, res) => {
    db.all('SELECT * FROM filieres', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

filieresRouter.post('/', restrictTo('chef_departement'), (req, res) => {
    const { nom } = req.body;
    if (!nom) return res.status(400).json({ error: 'Le nom de la filière est requis.' });
    db.run('INSERT INTO filieres (nom) VALUES (?)', [nom], function(err) {
        if (err && err.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ error: 'Cette filière existe déjà.' });
        }
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, nom });
    });
});

filieresRouter.put('/:id', restrictTo('chef_departement'), (req, res) => {
    const { nom } = req.body;
    db.run('UPDATE filieres SET nom = ? WHERE id = ?', [nom, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Filière non trouvée.' });
        res.json({ message: 'Filière mise à jour avec succès.' });
    });
});

filieresRouter.delete('/:id', restrictTo('chef_departement'), (req, res) => {
    db.run('DELETE FROM filieres WHERE id = ?', req.params.id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Filière non trouvée.' });
        res.json({ message: 'Filière supprimée avec succès.' });
    });
});

// --- ROUTES BUREAUX (CRUD) ---
bureauxRouter.get('/', (req, res) => {
    db.all('SELECT * FROM bureaux', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

bureauxRouter.post('/', restrictTo('chef_departement'), (req, res) => {
    const { nom } = req.body;
    if (!nom) return res.status(400).json({ error: 'Le nom du bureau est requis.' });
    db.run('INSERT INTO bureaux (nom) VALUES (?)', [nom], function(err) {
        if (err && err.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ error: 'Ce bureau existe déjà.' });
        }
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, nom });
    });
});

bureauxRouter.put('/:id', restrictTo('chef_departement'), (req, res) => {
    const { nom } = req.body;
    db.run('UPDATE bureaux SET nom = ? WHERE id = ?', [nom, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Bureau non trouvé.' });
        res.json({ message: 'Bureau mis à jour avec succès.' });
    });
});

bureauxRouter.delete('/:id', restrictTo('chef_departement'), (req, res) => {
    db.run('DELETE FROM bureaux WHERE id = ?', req.params.id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Bureau non trouvé.' });
        res.json({ message: 'Bureau supprimé avec succès.' });
    });
});

// ===================================
// DÉMARRAGE DU SERVEUR
// ===================================
app.listen(PORT, () => {
  console.log(`\n🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`📊 Base de données: SQLite (polytechnique.db)`);
  console.log(`🔐 Code sécurité chef département: ${CHEF_SECURITY_CODE}\n`);
});

process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('\n✓ Connexion à la base de données fermée');
    process.exit(0);
  });
});
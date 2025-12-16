// ===== SERVER.JS COMPLET AVEC NOTIFICATIONS ET DISCUSSIONS =====
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;


// Clé secrète pour le JWT
const JWT_SECRET = process.env.JWT_SECRET;
const CHEF_SECURITY_CODE = process.env.CHEF_SECURITY_CODE;


// Middleware
app.use(cors());
app.use(express.json());

// Connexion PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});


pool.connect()
  .then(() => {
    console.log('✓ Connecté à la base PostgreSQL');
    initDatabase();
  })
  .catch(err => console.error('Erreur PostgreSQL:', err));

// ===============================
// INITIALISATION DES TABLES
// ===============================
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        nom TEXT NOT NULL,
        prenom TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        statut TEXT NOT NULL CHECK(statut IN ('etudiant','enseignant','chef_departement')),
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS filieres (
        id SERIAL PRIMARY KEY,
        nom TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS bureaux (
        id SERIAL PRIMARY KEY,
        nom TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS salles (
        id SERIAL PRIMARY KEY,
        nom TEXT UNIQUE NOT NULL,
        capacite INTEGER NOT NULL,
        batiment TEXT NOT NULL,
        description TEXT,
        filiere_id INTEGER REFERENCES filieres(id) ON DELETE SET NULL,
        bureau_id INTEGER REFERENCES bureaux(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          (filiere_id IS NOT NULL AND bureau_id IS NULL) OR
          (filiere_id IS NULL AND bureau_id IS NOT NULL)
        )
      );

      CREATE TABLE IF NOT EXISTS discussions (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        read_status BOOLEAN DEFAULT false,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✓ Tables créées avec succès');
  } catch (err) {
    console.error('Erreur lors de la création des tables:', err);
  }
}

// ===============================
// MIDDLEWARES DE PROTECTION
// ===============================
function protect(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ error: 'Token invalide ou expiré' });
  }
}

function restrictTo(statut) {
  return (req, res, next) => {
    if (req.user.statut !== statut) {
      return res.status(403).json({ error: `Action réservée aux ${statut}` });
    }
    next();
  };
}

// ===============================
// ROUTES AUTHENTIFICATION
// ===============================
app.post('/api/auth/register', async (req, res) => {
  const { nom, prenom, email, statut, password, securityCode } = req.body;

  if (!nom || !prenom || !email || !statut || !password) {
    return res.status(400).json({ error: 'Tous les champs sont requis' });
  }
  if (!['etudiant','enseignant','chef_departement'].includes(statut)) {
    return res.status(400).json({ error: 'Statut invalide' });
  }
  if (statut === 'chef_departement' && securityCode !== CHEF_SECURITY_CODE) {
    return res.status(403).json({ error: 'Code de sécurité invalide' });
  }

  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (rows.length > 0) {
      return res.status(400).json({ error: 'Email déjà utilisé' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const insertRes = await pool.query(
      'INSERT INTO users (nom, prenom, email, statut, password) VALUES ($1,$2,$3,$4,$5) RETURNING id, nom, prenom, email, statut',
      [nom, prenom, email, statut, hashedPassword]
    );

    res.status(201).json({ message: 'Inscription réussie', user: insertRes.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const token = jwt.sign({ id: user.id, nom: user.nom, email: user.email, statut: user.statut }, JWT_SECRET, { expiresIn: '1d' });

    res.json({ message: 'Connexion réussie', token, user: { id: user.id, nom: user.nom, prenom: user.prenom, email: user.email, statut: user.statut } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// ROUTES UTILISATEURS
// ===============================
app.get('/api/users/chef-departement', protect, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, nom, prenom, email, statut, created_at FROM users WHERE statut=$1', ['chef_departement']);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// NOUVELLE ROUTE : MESSAGES NON LUS (pour notification)
// ===============================
app.get('/api/users/total-unread-messages', protect, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT COUNT(*) as total_unread FROM discussions WHERE receiver_id=$1 AND read_status=false',
      [req.user.id]
    );
    res.json({ total_unread: parseInt(rows[0].total_unread) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// ROUTES DISCUSSIONS COMPLÈTES
// ===============================
const discussionsRouter = express.Router();
app.use('/api/discussions', protect, discussionsRouter);

// 1. Récupérer toutes les conversations de l'utilisateur
discussionsRouter.get('/', async (req, res) => {
  const currentUserId = req.user.id;
  const currentUserStatut = req.user.statut;
  
  try {
    // Sous-requête pour obtenir tous les IDs de partenaires de conversation uniques
    const partnerIdsQuery = `
      SELECT DISTINCT CASE 
        WHEN sender_id = $1 THEN receiver_id 
        ELSE sender_id 
      END AS partner_id
      FROM discussions
      WHERE sender_id = $1 OR receiver_id = $1
    `;

    const { rows: partnerRows } = await pool.query(partnerIdsQuery, [currentUserId]);
    const partnerIds = partnerRows.map(row => row.partner_id).filter(id => id !== currentUserId);

    if (partnerIds.length === 0) {
      return res.json([]);
    }

    // Récupérer les infos des partenaires avec filtrage par statut
    let usersQuery = `
      SELECT id, nom, prenom, statut
      FROM users
      WHERE id = ANY($1::int[])
    `;
    
    if (currentUserStatut !== 'chef_departement') {
      usersQuery += ` AND statut = 'chef_departement'`;
    } else {
      usersQuery += ` AND statut != 'chef_departement'`;
    }

    const { rows: partners } = await pool.query(usersQuery, [partnerIds]);

    // Pour chaque partenaire, récupérer le dernier message et les messages non lus
    const conversations = await Promise.all(
      partners.map(async (partner) => {
        // Dernier message
        const lastMessageQuery = `
          SELECT message, sent_at
          FROM discussions
          WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)
          ORDER BY sent_at DESC
          LIMIT 1
        `;
        
        const { rows: lastMessageRows } = await pool.query(lastMessageQuery, [currentUserId, partner.id]);
        const lastMessage = lastMessageRows[0];

        // Messages non lus
        const unreadQuery = `
          SELECT COUNT(id) as unread_count
          FROM discussions
          WHERE sender_id = $1 AND receiver_id = $2 AND read_status = false
        `;
        
        const { rows: unreadRows } = await pool.query(unreadQuery, [partner.id, currentUserId]);
        const unreadCount = parseInt(unreadRows[0].unread_count);

        return {
          ...partner,
          lastMessage: lastMessage?.message,
          lastMessageSentAt: lastMessage?.sent_at,
          unreadCount: unreadCount
        };
      })
    );

    // Trier par date du dernier message (le plus récent d'abord)
    conversations.sort((a, b) => {
      if (!a.lastMessageSentAt && !b.lastMessageSentAt) return 0;
      if (!a.lastMessageSentAt) return 1;
      if (!b.lastMessageSentAt) return -1;
      return new Date(b.lastMessageSentAt) - new Date(a.lastMessageSentAt);
    });

    res.json(conversations);
  } catch (err) {
    console.error('Erreur lors de la récupération des conversations:', err);
    res.status(500).json({ error: err.message });
  }
});

// 2. Envoyer un message
discussionsRouter.post('/send', async (req, res) => {
  const { receiverId, message } = req.body;
  const senderId = req.user.id;
  const senderStatut = req.user.statut;

  if (!receiverId || !message) {
    return res.status(400).json({ error: 'ID du destinataire et message sont requis.' });
  }

  try {
    // Vérifier le destinataire
    const { rows: receiverRows } = await pool.query('SELECT statut FROM users WHERE id=$1', [receiverId]);
    const receiver = receiverRows[0];
    
    if (!receiver) {
      return res.status(404).json({ error: 'Destinataire introuvable.' });
    }

    // Vérification des autorisations
    if (senderStatut === 'chef_departement' && receiver.statut === 'chef_departement') {
      return res.status(403).json({
        error: 'Les chefs de département ne peuvent pas communiquer entre eux.'
      });
    }

    if (senderStatut !== 'chef_departement' && receiver.statut !== 'chef_departement') {
      return res.status(403).json({
        error: 'Les utilisateurs ne peuvent pas communiquer entre eux.'
      });
    }

    // Insérer le message
    const insertRes = await pool.query(
      'INSERT INTO discussions (sender_id, receiver_id, message) VALUES ($1,$2,$3) RETURNING id, sent_at',
      [senderId, receiverId, message]
    );

    res.status(201).json({
      message: 'Message envoyé',
      discussionId: insertRes.rows[0].id,
      sent_at: insertRes.rows[0].sent_at
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Récupérer les messages d'une conversation spécifique
discussionsRouter.get('/:partnerId', async (req, res) => {
  const currentUserId = req.user.id;
  const partnerId = req.params.partnerId;

  try {
    const { rows } = await pool.query(`
      SELECT d.id, d.sender_id, d.receiver_id, d.message, d.read_status, d.sent_at,
             s.nom AS sender_nom, s.prenom AS sender_prenom, s.statut AS sender_statut,
             r.nom AS receiver_nom, r.prenom AS receiver_prenom, r.statut AS receiver_statut
      FROM discussions d
      JOIN users s ON d.sender_id = s.id
      JOIN users r ON d.receiver_id = r.id
      WHERE (d.sender_id=$1 AND d.receiver_id=$2) OR (d.sender_id=$2 AND d.receiver_id=$1)
      ORDER BY d.sent_at ASC
    `, [currentUserId, partnerId]);

    // Marquer les messages comme lus
    await pool.query(
      'UPDATE discussions SET read_status=true WHERE receiver_id=$1 AND sender_id=$2 AND read_status=false',
      [currentUserId, partnerId]
    );

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// ROUTES CRUD SALLES, FILIERES, BUREAUX
// ===============================
const sallesRouter = express.Router();
const filieresRouter = express.Router();
const bureauxRouter = express.Router();

app.use('/api/salles', protect, sallesRouter);
app.use('/api/filieres', protect, filieresRouter);
app.use('/api/bureaux', protect, bureauxRouter);

// --- Salles CRUD ---
sallesRouter.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.id, s.nom, s.capacite, s.batiment, s.description, s.filiere_id, s.bureau_id,
             f.nom AS filiere_nom, b.nom AS bureau_nom
      FROM salles s
      LEFT JOIN filieres f ON s.filiere_id=f.id
      LEFT JOIN bureaux b ON s.bureau_id=b.id
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

sallesRouter.get('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT s.id, s.nom, s.capacite, s.batiment, s.description, s.filiere_id, s.bureau_id,
             f.nom AS filiere_nom, b.nom AS bureau_nom
      FROM salles s
      LEFT JOIN filieres f ON s.filiere_id=f.id
      LEFT JOIN bureaux b ON s.bureau_id=b.id
      WHERE s.id = $1
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Salle non trouvée' });
    }
    
    res.json(rows[0]);
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  }
});

sallesRouter.post('/', restrictTo('chef_departement'), async (req, res) => {
  const { nom, capacite, batiment, description, filiere_id, bureau_id } = req.body;
  if (!nom || !capacite || !batiment) return res.status(400).json({ error: 'Nom, capacité et bâtiment requis' });
  if ((filiere_id && bureau_id) || (!filiere_id && !bureau_id)) return res.status(400).json({ error: 'Assigner soit filière soit bureau' });

  try {
    const checkNom = await pool.query('SELECT id FROM salles WHERE nom=$1', [nom]);
    if (checkNom.rows.length > 0) return res.status(409).json({ error: 'Nom de salle déjà existant' });

    const checkUnique = filiere_id
      ? await pool.query('SELECT id FROM salles WHERE filiere_id=$1', [filiere_id])
      : await pool.query('SELECT id FROM salles WHERE bureau_id=$1', [bureau_id]);

    if (checkUnique.rows.length > 0) return res.status(409).json({ error: filiere_id ? 'Cette filière a déjà une salle' : 'Ce bureau a déjà une salle' });

    const insertRes = await pool.query(
      'INSERT INTO salles (nom, capacite, batiment, description, filiere_id, bureau_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [nom, capacite, batiment, description||null, filiere_id||null, bureau_id||null]
    );

    res.status(201).json(insertRes.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

sallesRouter.put('/:id', restrictTo('chef_departement'), async (req, res) => {
  const { id } = req.params;
  const { nom, capacite, batiment, description, filiere_id, bureau_id } = req.body;
  
  if (!nom || !capacite || !batiment) return res.status(400).json({ error: 'Nom, capacité et bâtiment requis' });
  if ((filiere_id && bureau_id) || (!filiere_id && !bureau_id)) return res.status(400).json({ error: 'Assigner soit filière soit bureau' });

  try {
    // Vérifier que la salle existe
    const checkSalle = await pool.query('SELECT id FROM salles WHERE id=$1', [id]);
    if (checkSalle.rows.length === 0) {
      return res.status(404).json({ error: 'Salle non trouvée' });
    }

    // Vérifier que le nom n'est pas déjà utilisé par une autre salle
    const checkNom = await pool.query('SELECT id FROM salles WHERE nom=$1 AND id!=$2', [nom, id]);
    if (checkNom.rows.length > 0) return res.status(409).json({ error: 'Nom de salle déjà existant' });

    // Vérifier l'unicité filière/bureau (sauf pour cette salle)
    const checkUnique = filiere_id
      ? await pool.query('SELECT id FROM salles WHERE filiere_id=$1 AND id!=$2', [filiere_id, id])
      : await pool.query('SELECT id FROM salles WHERE bureau_id=$1 AND id!=$2', [bureau_id, id]);

    if (checkUnique.rows.length > 0) return res.status(409).json({ error: filiere_id ? 'Cette filière a déjà une salle' : 'Ce bureau a déjà une salle' });

    const updateRes = await pool.query(
      'UPDATE salles SET nom=$1, capacite=$2, batiment=$3, description=$4, filiere_id=$5, bureau_id=$6, created_at=CURRENT_TIMESTAMP WHERE id=$7 RETURNING *',
      [nom, capacite, batiment, description||null, filiere_id||null, bureau_id||null, id]
    );

    res.json(updateRes.rows[0]);
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  }
});

sallesRouter.delete('/:id', restrictTo('chef_departement'), async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query('DELETE FROM salles WHERE id=$1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Salle non trouvée' });
    }
    
    res.json({ message: 'Salle supprimée avec succès', id: result.rows[0].id });
  } catch (err) {
    if (err.code === '23503') { // Foreign key violation
      return res.status(409).json({ error: 'Impossible de supprimer cette salle car elle est référencée ailleurs' });
    }
    res.status(500).json({ error: err.message });
  }
});

// --- Filieres CRUD ---
filieresRouter.get('/', async (req,res)=>{ 
  try { const { rows } = await pool.query('SELECT * FROM filieres ORDER BY nom'); res.json(rows); } 
  catch(err){ res.status(500).json({ error: err.message }); }
});

filieresRouter.get('/:id', async (req,res)=>{ 
  const { id } = req.params;
  try { 
    const { rows } = await pool.query('SELECT * FROM filieres WHERE id=$1', [id]); 
    if (rows.length === 0) return res.status(404).json({ error: 'Filière non trouvée' });
    res.json(rows[0]); 
  } 
  catch(err){ res.status(500).json({ error: err.message }); }
});

filieresRouter.post('/', restrictTo('chef_departement'), async (req,res)=>{
  const { nom } = req.body;
  if(!nom) return res.status(400).json({ error:'Nom requis' });
  try {
    const { rows } = await pool.query('INSERT INTO filieres (nom) VALUES ($1) RETURNING *', [nom]);
    res.status(201).json(rows[0]);
  } catch(err){
    if(err.code==='23505') return res.status(409).json({ error:'Filière déjà existante' });
    res.status(500).json({ error: err.message });
  }
});

filieresRouter.put('/:id', restrictTo('chef_departement'), async (req,res)=>{
  const { id } = req.params;
  const { nom } = req.body;
  if(!nom) return res.status(400).json({ error:'Nom requis' });
  
  try {
    // Vérifier que la filière existe
    const checkFiliere = await pool.query('SELECT id FROM filieres WHERE id=$1', [id]);
    if (checkFiliere.rows.length === 0) {
      return res.status(404).json({ error: 'Filière non trouvée' });
    }
    
    // Vérifier que le nom n'est pas déjà utilisé par une autre filière
    const checkNom = await pool.query('SELECT id FROM filieres WHERE nom=$1 AND id!=$2', [nom, id]);
    if (checkNom.rows.length > 0) return res.status(409).json({ error:'Filière déjà existante' });
    
    const { rows } = await pool.query('UPDATE filieres SET nom=$1 WHERE id=$2 RETURNING *', [nom, id]);
    res.json(rows[0]);
  } catch(err){
    if(err.code==='23505') return res.status(409).json({ error:'Filière déjà existante' });
    res.status(500).json({ error: err.message });
  }
});

filieresRouter.delete('/:id', restrictTo('chef_departement'), async (req,res)=>{
  const { id } = req.params;
  
  try {
    // Vérifier si des salles utilisent cette filière
    const checkSalles = await pool.query('SELECT id FROM salles WHERE filiere_id=$1', [id]);
    if (checkSalles.rows.length > 0) {
      return res.status(409).json({ error: 'Impossible de supprimer cette filière car elle est assignée à une ou plusieurs salles' });
    }
    
    const result = await pool.query('DELETE FROM filieres WHERE id=$1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Filière non trouvée' });
    }
    
    res.json({ message: 'Filière supprimée avec succès', id: result.rows[0].id });
  } catch(err){
    if (err.code === '23503') { // Foreign key violation
      return res.status(409).json({ error: 'Impossible de supprimer cette filière car elle est référencée ailleurs' });
    }
    res.status(500).json({ error: err.message });
  }
});

// --- Bureaux CRUD ---
bureauxRouter.get('/', async (req,res)=>{ 
  try { const { rows } = await pool.query('SELECT * FROM bureaux ORDER BY nom'); res.json(rows); } 
  catch(err){ res.status(500).json({ error: err.message }); }
});

bureauxRouter.get('/:id', async (req,res)=>{ 
  const { id } = req.params;
  try { 
    const { rows } = await pool.query('SELECT * FROM bureaux WHERE id=$1', [id]); 
    if (rows.length === 0) return res.status(404).json({ error: 'Bureau non trouvé' });
    res.json(rows[0]); 
  } 
  catch(err){ res.status(500).json({ error: err.message }); }
});

bureauxRouter.post('/', restrictTo('chef_departement'), async (req,res)=>{
  const { nom } = req.body;
  if(!nom) return res.status(400).json({ error:'Nom requis' });
  try {
    const { rows } = await pool.query('INSERT INTO bureaux (nom) VALUES ($1) RETURNING *', [nom]);
    res.status(201).json(rows[0]);
  } catch(err){
    if(err.code==='23505') return res.status(409).json({ error:'Bureau déjà existant' });
    res.status(500).json({ error: err.message });
  }
});

bureauxRouter.put('/:id', restrictTo('chef_departement'), async (req,res)=>{
  const { id } = req.params;
  const { nom } = req.body;
  if(!nom) return res.status(400).json({ error:'Nom requis' });
  
  try {
    // Vérifier que le bureau existe
    const checkBureau = await pool.query('SELECT id FROM bureaux WHERE id=$1', [id]);
    if (checkBureau.rows.length === 0) {
      return res.status(404).json({ error: 'Bureau non trouvé' });
    }
    
    // Vérifier que le nom n'est pas déjà utilisé par un autre bureau
    const checkNom = await pool.query('SELECT id FROM bureaux WHERE nom=$1 AND id!=$2', [nom, id]);
    if (checkNom.rows.length > 0) return res.status(409).json({ error:'Bureau déjà existant' });
    
    const { rows } = await pool.query('UPDATE bureaux SET nom=$1 WHERE id=$2 RETURNING *', [nom, id]);
    res.json(rows[0]);
  } catch(err){
    if(err.code==='23505') return res.status(409).json({ error:'Bureau déjà existant' });
    res.status(500).json({ error: err.message });
  }
});

bureauxRouter.delete('/:id', restrictTo('chef_departement'), async (req,res)=>{
  const { id } = req.params;
  
  try {
    // Vérifier si des salles utilisent ce bureau
    const checkSalles = await pool.query('SELECT id FROM salles WHERE bureau_id=$1', [id]);
    if (checkSalles.rows.length > 0) {
      return res.status(409).json({ error: 'Impossible de supprimer ce bureau car il est assigné à une ou plusieurs salles' });
    }
    
    const result = await pool.query('DELETE FROM bureaux WHERE id=$1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Bureau non trouvé' });
    }
    
    res.json({ message: 'Bureau supprimé avec succès', id: result.rows[0].id });
  } catch(err){
    if (err.code === '23503') { // Foreign key violation
      return res.status(409).json({ error: 'Impossible de supprimer ce bureau car il est référencé ailleurs' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ===============================
// DÉMARRAGE DU SERVEUR
// ===============================
app.listen(PORT, () => {
  console.log(`\n🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`🔐 Code sécurité chef département: ${CHEF_SECURITY_CODE}\n`);
});

process.on('SIGINT', () => {
  pool.end(() => {
    console.log('\n✓ Connexion PostgreSQL fermée');
    process.exit(0);
  });
});
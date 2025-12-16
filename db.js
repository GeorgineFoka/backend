const pool = new Pool({
  host: 'dpg-d5083m3uibrs73dteq90-a.render.com', // <- bien avec .render.com
  port: 5432,
  database: 'gestion_salle',
  user: 'gestion_salle_user',
  password: 'vS9OYa914HqjAbjxYp9pA6VuIxULwooZ',
  ssl: { rejectUnauthorized: false }
});

module.exports = {
  apps: [
    {
      name        : "gestion-ad",
      script      : "start.sh",
      interpreter : "bash",
      cwd         : "/var/scripts/gestion_usuarios",

      // Reiniciar automáticamente si el proceso muere
      autorestart : true,
      watch       : false,

      // Reiniciar si supera 300 MB de RAM
      max_memory_restart: "300M",

      // Variables de entorno (complementan al .env)
      env: {
        FLASK_ENV: "production",
      },

      // Log de pm2 (separado del log de la app)
      out_file : "/var/scripts/gestion_usuarios/logs/pm2_out.log",
      error_file: "/var/scripts/gestion_usuarios/logs/pm2_err.log",
      merge_logs: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
  ],
};

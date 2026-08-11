# Cosas a tener en cuenta de cara al despliegue
## Configuraciones actuales que, en un futuro, deberán cambiar para mantener la integridad de los datos de Ellysia

1. Actualmente, en la base de datos, el correo del usuario "root" es "gmiganescu@gmail.com", que es la cuenta personal de Gabriel Musteata Iganescu. De cara a un posible deploy, cuando se tengan las cuentas de correo de "ellysia.es", será necesario cambiarlo por "root@ellysia.es" o por "gmiganescu@ellysia.es".
2. Las URLs actuales en los archivos de configuración apuntan a "localhost" para facilitar el desarrollo; de cara a un despliegue, será necesario cambiarlo por el dominio "ellysia.es".
# Proyecto DNS Watcher
Intersección entre buenas prácticas para root zone, zonemaster y observatorio DNS para caracterizar los dominios.  

## 1. Pre-requisitos
# Observatorio

Software desarrollado con el fin de recolectar y analizar datos DNS de un conjunto de dominios.

---

## Requisitos Generales

### Geolite

Para geolocalizar las direcciones IP, es necesario obtener una llave para usar los servicios de Geolite, Maxmind. Puedes registrarte [aquí](https://www.maxmind.com/en/geolite2/signup). Esta llave debe ser guardada en el archivo de configuración `config.yml` con el nombre `geoiplicensekey`.

### PostgreSQL

- **Windows:** Sigue las instrucciones de instalación de [PostgreSQL en Windows](https://www.postgresql.org/download/windows/). Asegúrate de crear el usuario `postgres` con su contraseña y configurar el acceso adecuado.
- **Ubuntu:** Instala PostgreSQL usando:
  ```bash
  sudo apt-get install postgresql
  ```
  Configura el usuario y la base de datos ejecutando:
  ```bash
  sudo -u postgres psql postgres
  CREATE ROLE tu_usuario LOGIN PASSWORD 'tu_contraseña';
  CREATE DATABASE tu_base_de_datos OWNER tu_usuario;
  \q
  ```

### Go Lang

Instala Go Lang siguiendo las [instrucciones oficiales](https://golang.org/doc/install). Configura las variables de entorno `$GOROOT` y `$GOPATH`.

---

## Archivo de Configuración

Independientemente de si usarás Docker o no, es necesario configurar el archivo `config.yml`. Utiliza el archivo `config.yml.default` como plantilla y modifícalo según tus necesidades:

```yaml
# Geoip data
geoip:
    geoippath: Geolite
    geoipasnfilename: GeoLite2-ASN.mmdb
    geoipcountryfilename: GeoLite2-Country.mmdb
    geoiplicensekey: yourLicenseKey
# Database configurations
database:
    dbname: tu_base_de_datos
    dbuser: tu_usuario
    dbpass: tu_contraseña
    dbhost: localhost
    dbport: 5432
# Running arguments
runargs:
    inputfilepath: input-example.txt
    dontprobefilepath: dontprobefile.txt
    verbose: true
    concurrency: 100
    ccmax: 100
    maxretry: 2
    debug: false
    dnsservers: ["8.8.8.8", "1.1.1.1"]
```

---

## Instalación

### Sin Docker

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/niclabs/Observatorio.git
   ```

2. **Instala las dependencias:**
   ```bash
   go get github.com/miekg/dns
   go get github.com/oschwald/geoip2-golang
   go get github.com/lib/pq
   go get gopkg.in/yaml.v2
   ```

3. **Ejecuta el programa:**
   ```bash
   go run main/main.go
   ```

### Con Docker

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/niclabs/Observatorio.git
   ```

2. **Construye el contenedor:**
   ```bash
   docker build -t observatorio .
   ```

3. **Ejecuta el contenedor:**
   ```bash
   docker run observatorio
   ```

4. **Obtén los resultados:**
   ```bash
   docker cp <containerID>:/Observatorio/csvs/ <directorio_destino>
   ```

---

## Uso

- **Ejecución:** La ejecución puede tardar varios minutos u horas, dependiendo del tamaño de la lista de dominios y las capacidades de tu máquina.
- **Resultados:** Los resultados se generan en la carpeta `csvs` en formatos CSV y JSON.

Puedes visualizarlos usando el código disponible en [ObservatorioLAC-Graficos](https://github.com/niclabs/ObservatorioLAC-Graficos) o exportar los datos directamente desde la base de datos.

---

## Licencia

Este proyecto utiliza la licencia [MIT](LICENSE).

---

## Nota

- **Importante:** No subas información sensible al repositorio, como contraseñas, claves, nombres de bases de datos, o archivos de gran tamaño. Incluye estos archivos en el archivo `.gitignore`.
- **Diagrama de la Base de Datos:** Consulta el diseño [aquí](https://github.com/niclabs/Observatorio/wiki/database).


## Acknowledgments:

Observatorio:
@maitegm
@madestro
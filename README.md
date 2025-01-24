
# Repositorio Común: DNSwatcher

Este repositorio contiene dos proyectos principales relacionados con el diagnóstico y análisis de dominios DNS:

1. **DNSwatcher**: Intersección entre buenas prácticas para root zone, zonemaster y observatorio DNS para caracterizar los dominios.  

2. **DrDNS**: Herramienta para diagnósticos DNS mediante una API REST. Permite evaluar sincronía de registros SOA, autoridad, recursividad deshabilitada, soporte TCP y delegación de dominios.


---

## 1. Pre-instalación

Antes de comenzar, asegúrese de cumplir con los siguientes requisitos:

### Requisitos generales

- **Go**:
  - Descargue e instale Go desde [https://golang.org/doc/install](https://golang.org/doc/install).
  - Configure las variables de entorno `$GOROOT` y `$GOPATH`.

- **Docker**:
  - Se recomienda usar Docker para un entorno aislado y facilitar la configuración.

- **PostgreSQL** (necesario para Observatorio):
  - Instale PostgreSQL en su sistema y cree una base de datos. Instrucciones detalladas disponibles en `Base_Obs/README.md`.

- **Geolite** (necesario para Observatorio):
  - Obtenga una licencia gratuita de Geolite desde [MaxMind](https://www.maxmind.com/en/geolite2/signup).

---

## 2. Instalación

### Clonar el repositorio

```bash
git clone https://github.com/niclabs/dnswatcher.git
cd dnswatcher
```

### Configuración de cada proyecto

1. **DrDNS**:
  
   - Entrar a la carpeta DrDNS y configurar el módulo de go con las respectivas librerias. Para mayor información, revisar el archivo `DrDNS/README.md` para configurar y ejecutar la API REST.

2. **Observatorio**:
   - Configure los archivos necesarios como `config.yml`. Para mayor información, revisar el archivo `Base_Obs/README.md`.

---

## 3. Uso

### DrDNS

- Inicie el servidor:

  ```bash
  ./main_drdns
  ```

  Esto lanzará un servidor REST en el puerto `8080`. Puede cambiar el puerto modificando el archivo fuente.

- Realice una solicitud de diagnóstico:

  ```bash
  curl http://localhost:8080/DrDNS/example.com
  ```

  Esto devolverá un JSON con la información del diagnóstico.

### Observatorio

- Ejecute el contenedor Docker:

  ```bash
  docker run observatorio
  ```

  Esto recolectará datos DNS y generará archivos en formato `CSV` y `JSON` en la carpeta `csvs`.

- Para extraer los archivos generados:

  ```bash
  docker cp <containerID>:/Observatorio/csvs/ ./csvs
  ```

---

## 4. Licencia

Este proyecto está bajo la licencia [MIT](https://opensource.org/licenses/MIT). Consulte el archivo `LICENSE` para más detalles.

---

## 5. Notas adicionales

- **No suba información sensible** al repositorio, como contraseñas, nombres de bases de datos o archivos grandes de datos.
- Asegúrese de agregar los archivos de configuración sensibles (por ejemplo, `config.yml`) al archivo `.gitignore`.

Para más detalles sobre cada proyecto, consulte los archivos `README.md` dentro de las carpetas `DrDNS/` y `Base_Obs/`.


## **Contribuciones y Reconocimientos**

Este proyecto fue desarrollado basado en el proyecto 'Observatorio'.

Agradecimientos especiales a:

- @maitegm
- @madestro

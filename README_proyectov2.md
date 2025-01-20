# DNS Diagnóstico con API REST

Este software realiza diagnósticos DNS sobre dominios, evaluando sincronía de registros SOA, autoridad, recursividad deshabilitada, soporte TCP y delegación. Ahora, con soporte REST API, los diagnósticos pueden ser solicitados mediante peticiones HTTP y los resultados se retornan en formato JSON.

---

## **Pre-requisitos**

### 1. **Go**:
- Instale Go siguiendo las instrucciones en [https://golang.org/doc/install](https://golang.org/doc/install).
- Configure las variables de entorno `$GOROOT` y `$GOPATH` si es necesario.

### 2. **Dependencias de Go**:

Inicialice un módulo de Go:
```bash
go mod init dnswatcher
```

Instale las siguientes librerías:
```bash
go get github.com/gin-gonic/gin
```
```bash
go get github.com/miekg/dns
```
```bash
go get github.com/niclabs/dnswatcher/Base_Observatorio/dnsUtils
```
```bash
go get golang.org/x/net/idna
```

---

## Instalación del proyecto

Clonar este repositorio:

git clone <https://github.com/niclabs/dnswatcher.git>

Entrar al directorio del proyecto:

cd dnswatcher

Compilar la aplicación:

go build -o main_drdns

### Uso como REST API

Ejecutar el server:

./main_drdns

El servidor quedará disponible en el puerto 8080.

Solicitar un diagnóstico

Realice una petición HTTP GET a la ruta /DrDNS/{domain} donde {domain} es el dominio a analizar.

Ejemplo con curl:

curl http://localhost:8080/DrDNS/nic.cl

o simplemente ingresar el http en el buscador.

Respuesta esperada será el servidor retornando un JSON con la información correspondiente.

### Dockerización

#### Crear una imagen Docker para el proyecto:

Cree un archivo Dockerfile con el siguiente contenido:

FROM golang:1.23.4

WORKDIR /app
COPY . .

RUN go mod tidy
RUN go build -o main_drdns .

EXPOSE 8080
CMD ["./main_drdns"]

Construir el contenedor Docker:

docker build -t maindns-service .

Ejecute el contenedor:

docker run -p 8080:8080 maindns-service

Contribuciones y Reconocimientos

Este proyecto fue desarrollado con el apoyo de Observatorio.

Agradecimientos especiales a:

@maitegm

@madestro

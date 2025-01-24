# DNS Diagnóstico con API REST

Este software realiza diagnósticos DNS sobre dominios, evaluando sincronía de registros SOA, autoridad, recursividad deshabilitada, soporte TCP y delegación. Ahora, con soporte REST API, los diagnósticos pueden ser solicitados mediante peticiones HTTP y los resultados se retornan en formato JSON.

---

## **Pre-requisitos**

### 1. **Go**:
- Instale Go siguiendo las instrucciones en [https://golang.org/doc/install](https://golang.org/doc/install).
- Configure las variables de entorno `$GOROOT` y `$GOPATH` si es necesario.

---

## **Instalación del proyecto**

### 1. **Clonar este repositorio**

```bash
git clone https://github.com/niclabs/dnswatcher.git
```

o, en su defecto, descargar la última versión del repositorio:
```bash
git clone --depth 1 https://github.com/niclabs/dnswatcher.git
```


Entrar al directorio del proyecto:

```bash
cd dnswatcher
```

### 2. **Dependencias de Go**:

Inicializar un módulo de Go:
```bash
go mod init dnswatcher
```

Instale las librerías:
```bash
go mod tidy
```

Compilar la aplicación:

#### En Linux

```bash
go build -o main_drdns maindns_v2.go
```

#### En Windows

```bash
go build -o main_drdns.exe maindns_v2.go
```

## **Uso como REST API**

Ejecutar el server:

#### En Linux

```bash
./main_drdns
```

#### En Windows

```bash
main_drdns.exe
```

El servidor quedará disponible en el puerto `8080`. Si este puerto está en uso, se puede modificar la línea:

```go
log.Fatal(app.Listen(":8080"))
```

A un puerto alternativo como el `8081`


### Solicitar un diagnóstico

Realice una petición HTTP GET a la ruta `/DrDNS/{domain}` donde `{domain}` es el dominio a analizar.

Ejemplo con `curl`:

```bash
curl http://localhost:8080/DrDNS/nic.cl
```

O simplemente ingresar la URL en el navegador.

La respuesta esperada será un JSON con la información correspondiente.

---

## **Dockerización**

#### Crear una imagen Docker para el proyecto:

Cree un archivo Dockerfile, se deja un archivo base simple que sirve usando el localhost:

```dockerfile
FROM golang:1.23.4

WORKDIR /app
COPY . .

RUN go mod tidy
RUN go build -o main_drdns maindns_v2.go

EXPOSE 8080
CMD ["./main_drdns"]

```

Construir el contenedor Docker:

```bash
docker build -t maindns-service .
```

Ejecute el contenedor:

```bash
docker run -p 8080:8080 maindns-service
```

---




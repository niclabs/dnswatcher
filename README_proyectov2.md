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
go get github.com/niclabs/Observatorio/dnsUtils
```
```bash
go get golang.org/x/net/idna
```

---

## **Instalación del proyecto**

Clone este repositorio:
```bash
git clone <https://github.com/niclabs/dnswatcher.git>
```

Entre al directorio del proyecto:
```bash
cd dnswatcher
```

Compile la aplicación:
```bash
go build -o maindns_rest
```

---

## **Uso como REST API**

Ejecute el servidor:
```bash
./maindns_rest
```

El servidor quedará disponible en el puerto `8080`.

### **Solicitar un diagnóstico**

Realice una petición HTTP GET a la ruta `/analyze/{domain}` donde `{domain}` es el dominio a analizar.

Ejemplo con `curl`:
```bash
curl http://localhost:8080/analyze/google.com
```

### **Respuesta esperada**
El servidor retorna un JSON con el formato:
```json
[
  {
    "server": "ns1.example.com",
    "serial": 20230101,
    "serial_sync": true,
    "authority": true,
    "recursivity_off": true,
    "tcp": true
  },
  {
    "server": "ns2.example.com",
    "error": "NS no verificable: query timed out"
  }
]
```

---

## **Dockerización**

Cree una imagen Docker para el proyecto:

1. **Cree un archivo Dockerfile con el siguiente contenido:**
   ```dockerfile
   FROM golang:1.23.4

   WORKDIR /app
   COPY . .

   RUN go mod tidy
   RUN go build -o maindns_rest .

   EXPOSE 8080
   CMD ["./maindns_rest"]
   ```

2. **Construya la imagen Docker:**
   ```bash
   docker build -t maindns-service .
   ```

3. **Ejecute el contenedor:**
   ```bash
   docker run -p 8080:8080 maindns-service
   ```

---

## **Contribuciones y Reconocimientos**

- Este proyecto fue desarrollado con el apoyo de Observatorio.
- Agradecimientos especiales a:
  - @maitegm
  - @madestro

